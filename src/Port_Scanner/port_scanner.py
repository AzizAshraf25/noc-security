#!/usr/bin/env python3
"""TCP port scanner and exposure checker with two scan engines.

Engines
  builtin  pure-Python connect scan (no dependencies)
  nmap     runs nmap, parses its XML output and applies the same checks

For either engine the tool tells apart open / closed / filtered ports, can compare
the result with an "expected ports" policy (unexpected exposure, expected services
not reachable), writes JSON, and returns exit code 1 when the policy is violated.

Use it only on systems you own or are explicitly authorized to test.
"""

import argparse
import ipaddress
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
             993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
HTTP_PORTS = {80, 8000, 8008, 8080, 8081}
DEFAULT_THREADS, DEFAULT_TIMEOUT, DEFAULT_RETRIES = 100, 1.0, 1


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------
def parse_ports(spec):
    """Parse '22,80,443', '1-1024', 'top' or a mix into a sorted list of ports."""
    ports = set()
    for item in spec.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item == "top":
            ports.update(TOP_PORTS)
            continue
        start, _, end = item.partition("-")
        try:
            low = int(start)
            high = int(end) if end else low
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port spec: {item!r}")
        if not 1 <= low <= high <= 65535:
            raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
        ports.update(range(low, high + 1))
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    return sorted(ports)


def ports_to_spec(ports):
    """Compress [1,2,3,8,9] into '1-3,8-9' (compact nmap -p argument)."""
    ranges, start, prev = [], ports[0], ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append((start, prev))
        start = prev = port
    ranges.append((start, prev))
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)


def expand_targets(items):
    """Turn IPs, hostnames and CIDR networks into a de-duplicated list of IPv4 addresses."""
    targets = []
    for item in items:
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise SystemExit(f"Invalid network: {item}")
            if network.version != 4:
                raise SystemExit("IPv6 is not supported")
            targets += [str(ip) for ip in network.hosts()]
        else:
            try:
                targets.append(socket.gethostbyname(item))
            except socket.gaierror:
                raise SystemExit(f"Cannot resolve host: {item}")
    return list(dict.fromkeys(targets))


def read_targets_file(path):
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"Cannot read targets file: {exc}")
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]


def load_expected(path):
    """Load the expected-ports policy: {"<ip>": [ports], "*": [ports]}."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read expected-ports file: {exc}")
    expected = {}
    for host, ports in data.items():
        if host.startswith("_"):  # e.g. "_comment"
            continue
        if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
            raise SystemExit(f"Expected ports for {host!r} must be a list of integers")
        expected[host] = set(ports)
    return expected


def new_result():
    return {"open": [], "closed": 0, "filtered": 0, "states": {}, "services": {}}


# --------------------------------------------------------------------------
# Engine 1: built-in connect scan
# --------------------------------------------------------------------------
def probe(host, port, timeout, retries):
    """Return the state of one TCP port: 'open', 'closed' or 'filtered'.

    open     - the three-way handshake completed
    closed   - the host answered with a reset (RST): reachable, nothing listening
    filtered - no usable answer (dropped by a firewall, host down, or overloaded);
               the probe is retried `retries` more times before giving up
    """
    for _ in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except OSError:  # timeout, host/network unreachable, ...
            continue
    return "filtered"


def scan_builtin(targets, ports, threads, timeout, retries, track):
    """Probe every (host, port) pair with a pool of worker threads.

    `track` is the set of ports whose non-open state must be remembered
    (the ports mentioned in the expected-ports policy).
    """
    queue = Queue()
    for host in targets:
        for port in ports:
            queue.put((host, port))
    results = {h: new_result() for h in targets}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                host, port = queue.get_nowait()
            except Empty:
                return
            state = probe(host, port, timeout, retries)
            with lock:
                entry = results[host]
                if state == "open":
                    entry["open"].append(port)
                else:
                    entry[state] += 1
                    if port in track:
                        entry["states"][port] = state

    pool = [threading.Thread(target=worker) for _ in range(min(threads, queue.qsize()))]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return results


def grab_banner(host, port, timeout):
    """Read a short banner from an open port (best effort, never raises)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in HTTP_PORTS:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = sock.recv(512)
    except OSError:
        return ""
    lines = data.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return ""
    if port in HTTP_PORTS:
        server = next((l for l in lines if l.lower().startswith("server:")), "")
        text = f"{lines[0]} | {server}" if server else lines[0]
    else:
        text = lines[0]
    return "".join(ch for ch in text if ch.isprintable())[:80]


# --------------------------------------------------------------------------
# Engine 2: nmap wrapper
# --------------------------------------------------------------------------
def parse_nmap_xml(xml_text, targets, track):
    """Convert nmap XML output into the same per-host result structure as the built-in engine."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SystemExit(f"Could not parse nmap output: {exc}")
    results = {h: new_result() for h in targets}
    banners = {}
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None or addr.get("addr") not in results:
            continue
        ip = addr.get("addr")
        entry = results[ip]
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        # nmap collapses the most common state into <extraports>
        default_state = "closed"
        for extra in ports_el.findall("extraports"):
            kind = "filtered" if "filtered" in extra.get("state", "") else "closed"
            entry[kind] += int(extra.get("count", 0))
            default_state = kind
        for port_el in ports_el.findall("port"):
            if port_el.get("protocol") != "tcp":
                continue
            port = int(port_el.get("portid"))
            state = port_el.find("state").get("state")
            if state == "open":
                entry["open"].append(port)
                svc = port_el.find("service")
                if svc is not None:
                    entry["services"][port] = svc.get("name", "unknown")
                    text = " ".join(filter(None, (svc.get("product"), svc.get("version"),
                                                  svc.get("extrainfo"))))
                    if text:
                        banners[(ip, port)] = text[:80]
            else:
                kind = "filtered" if "filtered" in state else "closed"
                entry[kind] += 1
                if port in track:
                    entry["states"][port] = kind
        for port in track:  # tracked ports that nmap folded into <extraports>
            if port not in entry["open"] and port not in entry["states"]:
                entry["states"][port] = default_state
    return root, results, banners


def scan_nmap(targets, ports, args, track):
    exe = args.nmap_path or shutil.which("nmap")
    if not exe:
        sys.exit("nmap not found. Install it from https://nmap.org and add it to PATH, "
                 "or pass --nmap-path.")
    cmd = [exe, "-oX", "-", "-n", "-Pn", f"-{args.nmap_scan}", "-p", ports_to_spec(ports)]
    if args.banner:
        cmd += ["-sV", "--version-light"]
    if args.timing is not None:
        cmd.append(f"-T{args.timing}")
    if args.retries is not None:
        cmd += ["--max-retries", str(args.retries)]
    if args.timeout is not None:
        cmd += ["--max-rtt-timeout", f"{int(args.timeout * 1000)}ms"]
    if args.nmap_args:
        cmd += shlex.split(args.nmap_args, posix=(os.name != "nt"))
    cmd += targets

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        sys.exit(f"Could not run nmap: {exc}")
    if proc.returncode != 0:
        sys.exit(f"nmap failed (exit {proc.returncode}):\n{proc.stderr.strip()}")
    root, results, banners = parse_nmap_xml(proc.stdout, targets, track)
    info = {"engine": f"nmap {root.get('version', '')}".strip(), "nmap_command": root.get("args", "")}
    return results, banners, info


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------
def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def build_results(results, scanned_ports, banners, expected_map):
    scanned = set(scanned_ports)
    hosts = []
    for host, res in results.items():
        found = sorted(res["open"])
        expected = None
        if expected_map is not None:
            expected = expected_map.get(host, expected_map.get("*"))
        entry = {
            "host": host,
            "open": [{"port": p, "service": res["services"].get(p) or service_name(p),
                      "banner": banners.get((host, p), "")} for p in found],
            "counts": {"open": len(found), "closed": res["closed"], "filtered": res["filtered"]},
            "expected": sorted(expected) if expected is not None else None,
            "unexpected_open": [],
            "expected_down": [],
        }
        if expected is not None:
            entry["unexpected_open"] = sorted(set(found) - expected)
            entry["expected_down"] = [
                {"port": p, "state": res["states"].get(p, "closed")}
                for p in sorted((expected & scanned) - set(found))
            ]
        hosts.append(entry)
    return hosts


def print_report(hosts, show_banner):
    for entry in hosts:
        counts = entry["counts"]
        total = sum(counts.values())
        print(f"\n{entry['host']}")
        if not entry["open"]:
            print("  no open ports found")
        else:
            header = f"  {'PORT':<7}{'SERVICE':<12}" + ("BANNER" if show_banner else "")
            print(header.rstrip())
            for item in entry["open"]:
                row = f"  {item['port']:<7}{item['service']:<12}"
                print((row + item["banner"]).rstrip() if show_banner else row.rstrip())
        print(f"  ports: {counts['open']} open, {counts['closed']} closed, {counts['filtered']} filtered")
        if total and counts["filtered"] / total > 0.5:
            print("  [!] Most ports gave no response (filtered). The host may be down, firewalled or "
                  "overloaded. Try fewer --threads, a higher --timeout, or more --retries before "
                  "trusting this result.")
        if entry["unexpected_open"]:
            print(f"  [!] UNEXPECTED open: {', '.join(map(str, entry['unexpected_open']))}")
        if entry["expected_down"]:
            down = ", ".join(f"{d['port']} ({d['state']})" for d in entry["expected_down"])
            print(f"  [!] EXPECTED but not open: {down}")


def main():
    parser = argparse.ArgumentParser(description="TCP port scanner and exposure checker (builtin or nmap engine)")
    parser.add_argument("targets", nargs="*", help="IPs, hostnames or CIDR networks (e.g. 10.0.0.0/28)")
    parser.add_argument("-iL", "--input-file", help="file with one target per line (# for comments)")
    parser.add_argument("-p", "--ports", type=parse_ports, default="1-1024",
                        help="ports: 22,80,443 | 1-1024 | top (default: 1-1024)")
    parser.add_argument("--engine", choices=["builtin", "nmap"], default="builtin",
                        help="scan engine (default: builtin)")
    parser.add_argument("-t", "--threads", type=int,
                        help=f"worker threads, builtin only (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=float,
                        help=f"seconds per attempt (builtin default: {DEFAULT_TIMEOUT}; "
                             "nmap: max RTT timeout, unset by default so nmap adapts)")
    parser.add_argument("--retries", type=int,
                        help=f"extra attempts for ports that give no answer (builtin default: "
                             f"{DEFAULT_RETRIES}; nmap: its own default unless set)")
    parser.add_argument("--banner", action="store_true",
                        help="identify services (builtin: read banners; nmap: -sV --version-light)")
    parser.add_argument("--expected", help="JSON file with the expected open ports per host")
    parser.add_argument("--vantage", default="", help="where the scan runs from, e.g. LAN or WAN (recorded in the output)")
    parser.add_argument("--json", dest="json_path", help="write the results to this JSON file")
    parser.add_argument("--max-hosts", type=int, default=256,
                        help="refuse to scan more hosts than this (default: 256)")
    nm = parser.add_argument_group("nmap engine options")
    nm.add_argument("--nmap-path", help="path to nmap if it is not in PATH")
    nm.add_argument("--nmap-scan", choices=["sT", "sS"], default="sT",
                    help="sT = connect scan (no admin needed), sS = SYN scan (needs admin/root and Npcap on Windows)")
    nm.add_argument("--timing", type=int, choices=range(0, 6), help="nmap timing template 0-5 (-T)")
    nm.add_argument("--nmap-args", help='extra nmap arguments; write them with "=", e.g. --nmap-args="--reason"')
    args = parser.parse_args()

    items = list(args.targets)
    if args.input_file:
        items += read_targets_file(args.input_file)
    if not items:
        parser.error("give at least one target or use -iL")

    targets = expand_targets(items)
    if len(targets) > args.max_hosts:
        sys.exit(f"{len(targets)} hosts exceeds --max-hosts {args.max_hosts}; raise it deliberately if intended")
    expected_map = load_expected(args.expected) if args.expected else None
    track = set().union(*expected_map.values()) if expected_map else set()

    where = f' from "{args.vantage}"' if args.vantage else ""
    print(f"Scanning {len(targets)} host(s), {len(args.ports)} port(s) each, engine: {args.engine}{where}...")
    started = datetime.now()
    clock = time.time()

    banners = {}
    if args.engine == "nmap":
        if args.threads is not None:
            print("note: --threads is ignored by the nmap engine (use --timing instead)")
        results, banners, info = scan_nmap(targets, args.ports, args, track)
    else:
        threads = args.threads or DEFAULT_THREADS
        timeout = args.timeout if args.timeout is not None else DEFAULT_TIMEOUT
        retries = max(0, args.retries if args.retries is not None else DEFAULT_RETRIES)
        results = scan_builtin(targets, args.ports, threads, timeout, retries, track)
        if args.banner:
            for host, res in results.items():
                for port in res["open"]:
                    banners[(host, port)] = grab_banner(host, port, timeout)
        info = {"engine": "builtin", "threads": threads, "timeout": timeout, "retries": retries}

    duration = time.time() - clock
    hosts = build_results(results, args.ports, banners, expected_map)
    print_report(hosts, args.banner)

    total_open = sum(h["counts"]["open"] for h in hosts)
    unexpected = sum(len(h["unexpected_open"]) for h in hosts)
    down = sum(len(h["expected_down"]) for h in hosts)
    print(f"\nDone in {duration:.2f}s: {total_open} open port(s) on {len(hosts)} host(s)", end="")
    print(f", {unexpected} unexpected, {down} expected but not open" if expected_map is not None else "")

    if args.json_path:
        payload = {
            "scan": {"vantage": args.vantage, "started": started.isoformat(timespec="seconds"),
                     "duration_seconds": round(duration, 2), "ports_scanned": len(args.ports),
                     "targets": targets, **info},
            "hosts": hosts,
        }
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Results written to {out}")

    if expected_map is not None and (unexpected or down):
        sys.exit(1)


if __name__ == "__main__":
    main()