#!/usr/bin/env python3
"""Monitor socket activity with simple red-flag classification."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, order=True)
class Conn:
    proto: str
    local: str
    remote: str
    state: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Watch socket activity via ss output")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON lines")
    parser.add_argument("--show-closed", action="store_true", help="Also emit classified closed connections")
    return parser.parse_args()


def run_ss() -> list[Conn]:
    cmd = ["ss", "-tunH"]
    try:
        completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("'ss' binary not found") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{shlex.join(cmd)} failed: {exc.stderr.strip()}") from exc

    conns: list[Conn] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        local = parts[3]
        remote = parts[4]
        conns.append(Conn(proto=proto, local=local, remote=remote, state=state))
    return conns


def classify(conn: Conn) -> list[str]:
    reasons: list[str] = []
    remote = conn.remote.lower()
    if remote.endswith(":22"):
        reasons.append("ssh")
    if remote.endswith(":23"):
        reasons.append("telnet")
    if remote.endswith(":3389"):
        reasons.append("rdp")
    if conn.state in {"SYN-SENT", "SYN-RECV"}:
        reasons.append("handshake")
    if remote.startswith("0.0.0.0") or remote.startswith("[::]"):
        reasons.append("unspecified-remote")
    return reasons


def render_human(ts: str, event: str, conn: Conn, reasons: list[str]) -> str:
    return f"[{ts}] {event} {conn.proto} {conn.local} -> {conn.remote} ({conn.state}) reasons={','.join(reasons)}"


def render_json(ts: str, event: str, conn: Conn, reasons: list[str]) -> str:
    return json.dumps(
        {
            "ts": ts,
            "event": event,
            "proto": conn.proto,
            "local": conn.local,
            "remote": conn.remote,
            "state": conn.state,
            "reasons": reasons,
        },
        separators=(",", ":"),
    )


def main() -> int:
    args = parse_args()
    previous: set[Conn] = set()

    try:
        while True:
            current = set(run_ss())
            opened = current - previous
            closed = previous - current

            now = datetime.now(timezone.utc).isoformat()
            for conn in sorted(opened, key=lambda c: (c.proto, c.local, c.remote, c.state)):
                reasons = classify(conn)
                if not reasons:
                    continue
                print(render_json(now, "opened", conn, reasons) if args.json else render_human(now, "RED_FLAG", conn, reasons))

            if args.show_closed:
                for conn in sorted(closed, key=lambda c: (c.proto, c.local, c.remote, c.state)):
                    reasons = classify(conn)
                    if not reasons:
                        continue
                    print(render_json(now, "closed", conn, reasons) if args.json else render_human(now, "CLOSED", conn, reasons))

            previous = current
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
