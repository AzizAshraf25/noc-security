# Port Scanner

A TCP port scanner and **exposure checker** written in Python. It has two scan engines, the built-in connect scanner (no dependencies) and an **nmap wrapper**, and both feed the same checks: open / closed / filtered states, an expected-ports policy, JSON output, and exit codes for automation.

It is part of the NOC Security Toolkit and is used in the attack and defense rounds: scan the same targets from different network zones (LAN, WAN), compare the results with what the firewall should allow, and see what the monitoring detects.

> Use it only on systems you own or are explicitly authorized to test. Everything here was run in my own EVE-NG lab.

## Why two engines

| | `builtin` | `nmap` |
|---|---|---|
| Dependencies | none (Python only) | nmap installed |
| Speed control | fixed threads and timeout | nmap adapts its rate to the target |
| Service identification | reads banners | `-sV` (product and version) |
| SYN scan | no | yes (`--nmap-scan sS`, needs admin/root and Npcap on Windows) |
| Best for | quick checks, learning how scanning works | accurate scans of fragile or filtered targets |

The built-in engine sends all probes at a fixed pace, so a small virtual device can be overwhelmed and drop probes, which makes open ports look filtered. nmap slows down and retransmits when it sees loss. The wrapper keeps nmap's accuracy and adds the part that matters for NOC work: the policy check, the vantage label, JSON, and exit codes.

## Features

- Scans single hosts, hostnames, CIDR networks (`10.0.0.0/28`) or a targets file.
- Flexible ports: `22,80,443`, ranges like `1-1024`, or `top` (25 common service ports).
- Tells **open**, **closed** (reset received) and **filtered** (no answer) apart, and warns when most ports gave no answer.
- **Exposure check:** compare open ports with an expected-ports policy per host.
- JSON output with a `--vantage` label (where the scan ran from) and the engine and nmap command used.
- Exit code 1 when a policy is given and the scan deviates from it, so it can run in scheduled jobs.
- Safety guard: refuses to scan more than 256 hosts unless `--max-hosts` is raised on purpose.

## Usage

```bash
# built-in engine, one host, ports 1-1024
python3 port_scanner.py 192.168.100.3

# nmap engine with service identification
python3 port_scanner.py 192.168.100.3 -p 1-1024 --engine nmap --banner

# a small network, common ports, gentle timing for fragile devices
python3 port_scanner.py 192.168.100.0/29 -p top --engine nmap --timing 2

# exposure check against the expected-ports policy, labelled with where the scan runs from
python3 port_scanner.py 192.168.100.3 192.168.100.5 --expected expected_ports.json \
        --engine nmap --vantage WAN --json results/wan_scan.json

# extra nmap options (note the "=")
python3 port_scanner.py 192.168.100.3 --engine nmap --nmap-args="--reason"
```

| Option | Description | Default |
|---|---|---|
| `targets` | IPs, hostnames or CIDR networks | |
| `-iL`, `--input-file` | File with one target per line (`#` for comments) | |
| `-p`, `--ports` | `22,80`, `1-1024`, `top`, or a mix | `1-1024` |
| `--engine` | `builtin` or `nmap` | `builtin` |
| `--banner` | Identify services (builtin: banners; nmap: `-sV --version-light`) | off |
| `--expected` | JSON file with the expected open ports per host | |
| `--vantage` | Label for where the scan runs from (LAN, WAN, ...) | |
| `--json` | Write results to a JSON file | |
| `--max-hosts` | Refuse to scan more hosts than this | `256` |
| `-t`, `--threads` | Worker threads (builtin only) | `100` |
| `--timeout` | Seconds per attempt (builtin); max RTT timeout for nmap, unset by default | builtin `1.0` |
| `--retries` | Extra attempts for ports that give no answer | builtin `1`; nmap's own default |
| `--nmap-path` | Path to nmap if it is not in PATH | |
| `--nmap-scan` | `sT` connect scan (no admin) or `sS` SYN scan | `sT` |
| `--timing` | nmap timing template 0-5 (`-T`) | nmap default |
| `--nmap-args` | Extra nmap arguments, written as `--nmap-args="..."` | |

On Windows install nmap from nmap.org. If `nmap` is not found in PATH, pass `--nmap-path "C:\Program Files (x86)\Nmap\nmap.exe"`.

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
- **Expected but not open:** a port in the policy is closed or filtered. The service is down or blocked (availability issue). The state tells you which.

Only ports inside the scanned range are checked, so scan the range that covers your policy.

## Example output

```
Scanning 1 host(s), 11 port(s) each, engine: nmap from "LAN"...

127.0.0.1
  PORT   SERVICE
  8765   ultraseek-http
  8766   amcs
  ports: 2 open, 9 closed, 0 filtered
  [!] UNEXPECTED open: 8766
  [!] EXPECTED but not open: 8767 (closed), 8770 (closed)

Done in 0.03s: 2 open port(s) on 1 host(s), 1 unexpected, 2 expected but not open
```

Without `--banner`, nmap's service names come from its port table and are only guesses. Use `--banner` to identify what is really running.

## JSON output

```json
{
  "scan": {"vantage": "LAN", "started": "...", "duration_seconds": 0.03,
           "ports_scanned": 11, "targets": ["127.0.0.1"],
           "engine": "nmap 7.94SVN", "nmap_command": "nmap -oX - -n -Pn -sT -p 8760-8770 ..."},
  "hosts": [
    {"host": "127.0.0.1",
     "open": [{"port": 8765, "service": "http", "banner": "SimpleHTTPServer 0.6 Python 3.12.3"}],
     "counts": {"open": 2, "closed": 9, "filtered": 0},
     "expected": [8765, 8767, 8770],
     "unexpected_open": [8766],
     "expected_down": [{"port": 8767, "state": "closed"}, {"port": 8770, "state": "closed"}]}
  ]
}
```

The nmap command is stored in the JSON so every result can be reproduced.

## How it uses the lab

Run the same scan from each zone and compare the JSON files:

1. **Baseline:** write the expected-ports policy for each device.
2. **Scan from the LAN and from the WAN** with different `--vantage` labels.
3. **Compare** what the firewall exposes against the policy, and check whether the monitoring noticed the scan.
4. **Harden and re-scan** to show the exposure was closed.

The results feed the Attack Matrix: scan, blocked or open, detected or not, alert or not.

## How it works

- `parse_ports()` and `expand_targets()` turn the arguments into a list of ports and IPv4 addresses.
- **builtin:** all `(host, port)` pairs go into a thread-safe `Queue`; workers call `probe()`, which uses a full TCP connect. A completed handshake means open, a reset (RST) means closed, and no answer after the retries means filtered.
- **nmap:** `scan_nmap()` builds the nmap command, runs it without a shell, and `parse_nmap_xml()` converts the XML (`<port>` and `<extraports>` elements) into the same result structure.
- `build_results()` applies the policy and `print_report()` / JSON output are shared by both engines.

A full connect scan completes the handshake, so the target and the firewall log every connection. That is intentional for this project: those log entries are the input for the log analyzer.

## Limitations

- TCP only, IPv4 only, no OS detection.
- A filtered port and a dead host look the same (no answer). Treat a result where most ports are filtered with suspicion.
- The built-in engine is not adaptive; prefer the nmap engine for virtual switches and routers.
- Version detection (`--banner` with nmap) is slow and sends extra probes.
- Dead hosts cost time with the built-in engine: every port waits for the timeout.


## Roadmap

- [x] Multi-target scanning, policy check, JSON output
- [x] open / closed / filtered states and retries
- [x] nmap engine wrapper