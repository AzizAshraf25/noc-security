# Port Scanner

A multi-target TCP port scanner written in Python (standard library only) that does more than list open ports: it checks the result against an **expected-ports policy** and reports unexpected exposure and expected services that are down.

It is part of the NOC Security Toolkit and is used in the attack and defense rounds: scan the same targets from different network zones (LAN, WAN), compare the results with what the firewall should allow, and see what the monitoring detects.

> Use it only on systems you own or are explicitly authorized to test. Everything here was run in my own EVE-NG lab.

## Features

- Scans single hosts, hostnames, CIDR networks (`10.0.0.0/28`) or a targets file.
- Flexible ports: `22,80,443`, ranges like `1-1024`, or `top` (25 common service ports).
- Multi-threaded, with adjustable thread count and timeout.
- Optional banner grabbing to identify services (SSH banners, HTTP status and `Server` header).
- **Exposure check:** compare open ports with an expected-ports policy per host.
- JSON output with a `--vantage` label (where the scan ran from) for before/after comparisons.
- Exit code 1 when a policy is given and the scan deviates from it, so it can run in scheduled jobs.
- Safety guard: refuses to scan more than 256 hosts unless `--max-hosts` is raised on purpose.

## Usage

```bash
# one host, default ports 1-1024
python3 port_scanner.py 192.168.100.3

# common ports on a small network, with banners
python3 port_scanner.py 192.168.100.0/29 -p top --banner

# targets from a file, results saved as JSON, labelled with where the scan runs from
python3 port_scanner.py -iL targets.txt -p 1-1024 --vantage WAN --json results/wan_scan.json

# exposure check against the expected-ports policy
python3 port_scanner.py 192.168.100.3 192.168.100.5 -p 1-1024 --expected expected_ports.json --vantage LAN
```

| Option | Description | Default |
|---|---|---|
| `targets` | IPs, hostnames or CIDR networks | |
| `-iL`, `--input-file` | File with one target per line (`#` for comments) | |
| `-p`, `--ports` | `22,80`, `1-1024`, `top`, or a mix | `1-1024` |
| `-t`, `--threads` | Worker threads | `100` |
| `--timeout` | Seconds to wait per port | `1.0` |
| `--banner` | Grab service banners from open ports | off |
| `--expected` | JSON file with the expected open ports per host | |
| `--vantage` | Label for where the scan runs from (LAN, WAN, ...) | |
| `--json` | Write results to a JSON file | |
| `--max-hosts` | Refuse to scan more hosts than this | `256` |

## Expected-ports policy

A simple JSON file: the ports that are **allowed to be open** on each host. `*` applies to hosts that are not listed.

```json
{
  "192.168.100.3": [22],
  "192.168.100.5": [22, 80, 443, 10051],
  "*": []
}
```

The scanner reports two kinds of deviation:

- **Unexpected open:** a port is open but not in the policy. This is an exposure (security issue).
- **Expected but closed:** a port in the policy is closed. The service is down or blocked (availability issue).

Only ports inside the scanned range are checked, so scan the range that covers your policy.

## Example output

```
Scanning 1 host(s), 101 port(s) each from "LAN"...

127.0.0.1
  PORT   SERVICE     BANNER
  8765   unknown
  8766   unknown
  [!] UNEXPECTED open: 8766
  [!] EXPECTED but closed: 8770

Done in 2.01s: 2 open port(s) on 1 host(s), 1 unexpected, 1 expected but closed
```

## JSON output

```json
{
  "scan": {"vantage": "LAN", "started": "...", "duration_seconds": 2.01,
           "ports_scanned": 101, "targets": ["127.0.0.1"]},
  "hosts": [
    {"host": "127.0.0.1",
     "open": [{"port": 8765, "service": "unknown", "banner": ""}],
     "expected": [8765, 8770],
     "unexpected_open": [8766],
     "expected_closed": [8770]}
  ]
}
```

## How it uses the lab

Run the same scan from each zone and compare the JSON files:

1. **Baseline:** write the expected-ports policy for each device.
2. **Scan from the LAN and from the WAN** with different `--vantage` labels.
3. **Compare** what the firewall exposes against the policy, and check whether the monitoring noticed the scan.
4. **Harden and re-scan** to show the exposure was closed.

The results feed the Attack Matrix: scan, blocked or open, detected or not, alert or not.

## How it works

- `parse_ports()` and `expand_targets()` turn the arguments into a list of ports and IPv4 addresses.
- All `(host, port)` pairs go into a thread-safe `Queue`; each worker takes pairs, calls `scan_port()`, and stores open ports under a `Lock`.
- `scan_port()` uses `connect_ex()`, which completes the full TCP three-way handshake. Open ports answer SYN/ACK, closed ports answer RST, and filtered ports (dropped by a firewall) give no answer, which is why the timeout matters.
- `grab_banner()` reads the first line a service sends, or sends a `HEAD` request on common HTTP ports.
- `build_results()` compares open ports with the policy.

Because the handshake completes, the target and the firewall log every connection, which makes this scan easy to detect. That is intentional for this project: those log entries are the input for the log analyzer.

## Limitations

- TCP connect scan only: no UDP, no SYN (half-open) scan, no OS detection.
- IPv4 only.
- Dead hosts cost time: every port waits for the timeout. Use `-p top` or a lower `--timeout` for large ranges.
- A filtered port and a dropped host look the same (no answer).

## Notes

- (fill in: what I learned, in my own words)
- (fill in: how I used AI assistance, and what I reviewed, tested and changed myself)

## Roadmap

- [x] Multi-target scanning, banners, policy check, JSON output
- [ ] Compare two JSON scans automatically (before/after)
- [ ] Send deviations to Telegram and Zabbix
- [ ] SYN scan with Scapy