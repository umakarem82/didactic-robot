# didactic-robot

Host-level socket monitoring with red-flag classification, GeoIP enrichment, and
process attribution.

## What's in this repo

| File | Purpose |
| --- | --- |
| `net_watch_plus.py` | The active monitor. Polls `ss -tunHp` (Linux) or `lsof` (macOS), diffs snapshots, classifies new connections against the risky-port list, enriches with GeoIP / AbuseIPDB / rDNS, and attributes each flagged connection to a local PID + process name. |
| `SECURITY.md` | Security policy / vulnerability reporting. |

## Why `net_watch_plus.py` replaced `net_watch.py`

The original `net_watch.py` had a critical column-indexing bug in its `ss` parser
that caused it to read the *local* address into the `remote` field. As a result,
its classifier silently checked the wrong side of every connection and missed
all outbound traffic to risky ports. It also lacked process attribution, GeoIP,
and threat-intel enrichment — the features that make this kind of monitor
actually useful during an investigation.

`net_watch_plus.py` is the corrected, full-featured successor. See the header
docstring inside the script for the full feature list.

## Quick start

```bash
# Linux: run with sudo so process attribution works (-p in `ss` requires it)
sudo python3 net_watch_plus.py --home-country US

# Offline mode (no GeoIP / AbuseIPDB / rDNS lookups)
sudo python3 net_watch_plus.py --no-enrich

# Optional: enable AbuseIPDB enrichment
export ABUSEIPDB_KEY=your_key_here
sudo python3 net_watch_plus.py --home-country US
```

Events are written as JSON lines to `./net_watch_plus.jsonl` by default; use
`jq` to hunt through them. Pass `--webhook <url>` to forward high-severity
events to a webhook.

## Notes

- Tested against Python 3.11 on Ubuntu 22.04.
- Only the standard library is required; AbuseIPDB and webhook posting use
  `urllib`, no third-party packages needed.
