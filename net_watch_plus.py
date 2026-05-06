#!/usr/bin/env python3
"""
net_watch_plus.py
=================

An extended successor to the original `net_watch.py` (umakarem82/didactic-robot#1).

What this script does
---------------------
1.  Polls the kernel's socket table via `ss -tunHp` (Linux) or `lsof -nP -iTCP -iUDP`
    (macOS) every `--interval` seconds, and computes opened/closed deltas between
    polls so it doesn't spam on already-known sessions.
2.  Classifies each new connection against the full "red flag" port list discussed
    in the hardening guide: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 445 (SMB),
    1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC),
    6379 (Redis), 8080/8443 (HTTP-alt). Plus connection-state heuristics:
    SYN-SENT / SYN-RECV outbound handshakes, and unspecified remotes.
3.  Enriches each flagged remote IP with:
       - GeoIP country / ASN  (ip-api.com, free, 45 req/min, no key)
       - Abuse score          (AbuseIPDB v2, optional, key via $ABUSEIPDB_KEY)
       - Local rDNS           (best-effort, short timeout)
    Lookups are cached in-memory so the same IP isn't re-queried repeatedly.
4.  Attributes every flagged connection to a local PID + process name when running
    with sufficient privileges, so you actually know *what* on your box is talking.
5.  Emits each event in two places at once:
       - human-readable line on stdout (or stderr, --quiet to suppress)
       - JSON Lines to a local log file (--logfile, default: net_watch_plus.jsonl)
       - optional outbound POST to a webhook (--webhook URL), with a configurable
         minimum severity (--webhook-min-severity).
6.  Degrades gracefully when offline, when the AbuseIPDB key is absent, when run
    as a non-root user (limited PID visibility), or on macOS where `ss` is absent.

Author: Manus AI
License: MIT-style; use freely.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration: which ports / states are "red flags"
# ---------------------------------------------------------------------------

RISKY_PORTS: dict[int, str] = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    445:  "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

# Severity ranking is used so a webhook can filter on minimum severity.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Which classifier reasons map to which severity.
REASON_SEVERITY = {
    "telnet":             "critical",
    "smb":                "critical",
    "rdp":                "critical",
    "ftp":                "high",
    "vnc":                "high",
    "redis":              "high",
    "mysql":              "high",
    "mssql":              "high",
    "postgres":           "high",
    "smtp":               "medium",
    "ssh":                "medium",
    "http-alt":           "low",
    "https-alt":          "low",
    "handshake":          "low",
    "unspecified-remote": "info",
    "abusive-ip":         "critical",
    "foreign-country":    "medium",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Conn:
    proto: str
    local: str
    remote: str
    state: str
    pid: Optional[int] = None
    proc: Optional[str] = None

    def remote_ip_and_port(self) -> tuple[Optional[str], Optional[int]]:
        return _split_ip_port(self.remote)


@dataclass
class Enrichment:
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    rdns: Optional[str] = None
    abuse_score: Optional[int] = None
    abuse_reports: Optional[int] = None
    last_reported: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _split_ip_port(addr: str) -> tuple[Optional[str], Optional[int]]:
    """Parse an address string like '1.2.3.4:443' or '[::1]:80' -> (ip, port)."""
    if not addr or addr == "*":
        return None, None
    s = addr.strip()
    # IPv6 with brackets
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        port = port.lstrip(":")
        try:
            return host, int(port) if port and port != "*" else None
        except ValueError:
            return host, None
    # IPv6 without brackets but with multiple colons -> last colon is port separator
    if s.count(":") > 1:
        host, _, port = s.rpartition(":")
        try:
            return host, int(port) if port and port != "*" else None
        except ValueError:
            return host, None
    host, _, port = s.partition(":")
    try:
        return host, int(port) if port and port != "*" else None
    except ValueError:
        return host, None


def _is_private_or_special(ip: str) -> bool:
    """True for RFC1918 / loopback / link-local / multicast / unspecified."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
    )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Connection collection: ss (Linux) or lsof (macOS)
# ---------------------------------------------------------------------------

def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def collect_connections() -> list[Conn]:
    """Return current TCP+UDP connections with PID/proc when available."""
    system = platform.system()
    if system == "Linux" and _have("ss"):
        return _collect_via_ss()
    if _have("lsof"):
        return _collect_via_lsof()
    raise RuntimeError(
        "Neither 'ss' nor 'lsof' is available; install iproute2 (Linux) or use macOS."
    )


def _collect_via_ss() -> list[Conn]:
    cmd = ["ss", "-tunHp"]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{shlex.join(cmd)} failed: {exc.stderr.strip()}") from exc

    conns: list[Conn] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, state, local, remote = parts[0], parts[1], parts[3], parts[4]
        pid, proc = _parse_ss_users("".join(parts[5:]) if len(parts) > 5 else "")
        conns.append(Conn(proto=proto, local=local, remote=remote, state=state,
                          pid=pid, proc=proc))
    return conns


def _parse_ss_users(blob: str) -> tuple[Optional[int], Optional[str]]:
    """Parse the users:(("name",pid=123,fd=4)) field from ss -p output."""
    # blob may look like: users:(("python3",pid=12345,fd=7))
    if "pid=" not in blob:
        return None, None
    try:
        pname = blob.split('"')[1]
        pid_part = blob.split("pid=")[1]
        pid = int(pid_part.split(",")[0])
        return pid, pname
    except (IndexError, ValueError):
        return None, None


def _collect_via_lsof() -> list[Conn]:
    """macOS / fallback path. Coarser state info than ss."""
    cmd = ["lsof", "-nP", "-iTCP", "-iUDP", "-FpcPnT"]
    try:
        out = subprocess.run(cmd, check=False, capture_output=True, text=True).stdout
    except FileNotFoundError as exc:
        raise RuntimeError("'lsof' not found") from exc

    conns: list[Conn] = []
    pid: Optional[int] = None
    proc: Optional[str] = None
    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            pid = int(val)
            proc = None
        elif tag == "c":
            proc = val
        elif tag == "n":
            # Examples:
            #   1.2.3.4:55012->5.6.7.8:443
            #   *:22 (LISTEN)
            #   [::1]:631
            arrow = "->"
            local, remote = val, "*:*"
            state = "UNKNOWN"
            if arrow in val:
                local, remote = val.split(arrow, 1)
            # state may be appended in parentheses for TCP
            if "(" in remote and remote.endswith(")"):
                remote, _, state = remote.rpartition(" ")
                state = state.strip("()")
            conns.append(Conn(proto="tcp", local=local.strip(),
                              remote=remote.strip(), state=state,
                              pid=pid, proc=proc))
    return conns


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify_basic(conn: Conn) -> list[str]:
    """Port- and state-based reasons (no network calls)."""
    reasons: list[str] = []
    _, port = conn.remote_ip_and_port()
    if port and port in RISKY_PORTS:
        reasons.append(RISKY_PORTS[port])
    if conn.state in {"SYN-SENT", "SYN-RECV", "SYN_SENT", "SYN_RECV"}:
        reasons.append("handshake")
    if conn.remote.startswith("0.0.0.0") or conn.remote.startswith("[::]"):
        reasons.append("unspecified-remote")
    return reasons


# ---------------------------------------------------------------------------
# Enrichment: GeoIP, AbuseIPDB, rDNS
# ---------------------------------------------------------------------------

class Enricher:
    def __init__(self, abuseipdb_key: Optional[str], home_country: Optional[str],
                 timeout: float = 4.0) -> None:
        self.key = abuseipdb_key
        self.home_country = home_country.upper() if home_country else None
        self.timeout = timeout
        self._cache: dict[str, Enrichment] = {}
        # ip-api.com free tier: 45 req/min from a single IP. Throttle softly.
        self._last_geo_call = 0.0

    def enrich(self, ip: str) -> Enrichment:
        if ip in self._cache:
            return self._cache[ip]
        if _is_private_or_special(ip):
            e = Enrichment(country="private", country_code="--")
            self._cache[ip] = e
            return e

        e = Enrichment()
        self._geoip(ip, e)
        self._abuseipdb(ip, e)
        self._rdns(ip, e)
        self._cache[ip] = e
        return e

    def _geoip(self, ip: str, e: Enrichment) -> None:
        # Soft rate-limit: at most ~30 req/min to stay below the 45 limit.
        delta = time.time() - self._last_geo_call
        if delta < 2.0:
            time.sleep(2.0 - delta)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,as"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                data = json.loads(r.read().decode())
            if data.get("status") == "success":
                e.country = data.get("country")
                e.country_code = data.get("countryCode")
                e.isp = data.get("isp")
                e.asn = data.get("as")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            pass
        self._last_geo_call = time.time()

    def _abuseipdb(self, ip: str, e: Enrichment) -> None:
        if not self.key:
            return
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(
            url,
            headers={"Key": self.key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode()).get("data", {})
            e.abuse_score = data.get("abuseConfidenceScore")
            e.abuse_reports = data.get("totalReports")
            e.last_reported = data.get("lastReportedAt")
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            pass

    def _rdns(self, ip: str, e: Enrichment) -> None:
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            e.rdns = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
        finally:
            socket.setdefaulttimeout(old)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def severity_for(reasons: list[str]) -> str:
    if not reasons:
        return "info"
    return max(reasons, key=lambda r: SEVERITY_RANK.get(REASON_SEVERITY.get(r, "info"), 0)) \
        and max(
            (REASON_SEVERITY.get(r, "info") for r in reasons),
            key=lambda s: SEVERITY_RANK[s],
        )


# ---------------------------------------------------------------------------
# Output sinks
# ---------------------------------------------------------------------------

def render_human(ts: str, event: str, conn: Conn, reasons: list[str],
                 enr: Enrichment, severity: str) -> str:
    proc = f"{conn.proc}({conn.pid})" if conn.proc else "?"
    geo = f"{enr.country_code or '??'}/{enr.isp or '?'}"
    abuse = ""
    if enr.abuse_score is not None:
        abuse = f" abuse={enr.abuse_score}%"
    return (f"[{ts}] {severity.upper():8} {event:6} {conn.proto} "
            f"{conn.local} -> {conn.remote} ({conn.state}) "
            f"[{geo}{abuse} rdns={enr.rdns or '-'}] "
            f"by={proc} reasons={','.join(reasons)}")


def event_record(ts: str, event: str, conn: Conn, reasons: list[str],
                 enr: Enrichment, severity: str) -> dict:
    return {
        "ts": ts,
        "event": event,
        "severity": severity,
        "reasons": reasons,
        "conn": asdict(conn),
        "remote_ip": conn.remote_ip_and_port()[0],
        "remote_port": conn.remote_ip_and_port()[1],
        "enrichment": asdict(enr),
    }


def post_webhook(url: str, payload: dict, timeout: float = 4.0) -> None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=timeout).read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # Don't crash the watcher because the webhook is down.
        print(f"WARN: webhook POST failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extended socket red-flag watcher")
    p.add_argument("--interval", type=float, default=2.0,
                   help="Polling interval in seconds (default 2.0)")
    p.add_argument("--logfile", default="net_watch_plus.jsonl",
                   help="Path to append JSONL events (default ./net_watch_plus.jsonl)")
    p.add_argument("--webhook", default=None,
                   help="Optional webhook URL to POST events to")
    p.add_argument("--webhook-min-severity", default="high",
                   choices=list(SEVERITY_RANK),
                   help="Minimum severity that triggers webhook (default high)")
    p.add_argument("--home-country", default=None,
                   help="ISO-2 code for your country, e.g. US. "
                        "Connections to other countries get a 'foreign-country' tag.")
    p.add_argument("--show-closed", action="store_true",
                   help="Also emit classified closed connections")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress stdout; only write to logfile / webhook")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip GeoIP / AbuseIPDB / rDNS lookups (offline mode)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    abuse_key = os.environ.get("ABUSEIPDB_KEY") or None
    enricher = None if args.no_enrich else Enricher(
        abuseipdb_key=abuse_key, home_country=args.home_country
    )

    log_path = Path(args.logfile).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fp = log_path.open("a", buffering=1)  # line-buffered

    if not args.quiet:
        print(f"# net_watch_plus started at {_utc_now_iso()} "
              f"(interval={args.interval}s, log={log_path}, "
              f"abuseipdb={'on' if abuse_key else 'off'}, "
              f"home_country={args.home_country or 'unset'})",
              file=sys.stderr)

    previous: set[Conn] = set()

    try:
        while True:
            try:
                current = set(collect_connections())
            except RuntimeError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2

            opened = current - previous
            closed = previous - current

            for event_name, group in (("opened", opened),
                                      ("closed", closed if args.show_closed else set())):
                for conn in sorted(group, key=lambda c: (c.proto, c.local, c.remote, c.state)):
                    reasons = classify_basic(conn)

                    ip, _ = conn.remote_ip_and_port()
                    enr = Enrichment()
                    if enricher and ip and not _is_private_or_special(ip):
                        enr = enricher.enrich(ip)
                        if enr.abuse_score is not None and enr.abuse_score >= 25:
                            reasons.append("abusive-ip")
                        if (args.home_country and enr.country_code
                                and enr.country_code != args.home_country.upper()
                                and enr.country_code != "--"):
                            reasons.append("foreign-country")

                    if not reasons:
                        continue

                    sev = severity_for(reasons)
                    ts = _utc_now_iso()
                    record = event_record(ts, event_name, conn, reasons, enr, sev)

                    log_fp.write(json.dumps(record, separators=(",", ":")) + "\n")

                    if not args.quiet:
                        print(render_human(ts, event_name, conn, reasons, enr, sev))

                    if args.webhook and SEVERITY_RANK[sev] >= SEVERITY_RANK[args.webhook_min_severity]:
                        post_webhook(args.webhook, record)

            previous = current
            time.sleep(args.interval)

    except KeyboardInterrupt:
        return 0
    finally:
        log_fp.close()


if __name__ == "__main__":
    raise SystemExit(main())
