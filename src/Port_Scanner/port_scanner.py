#!/usr/bin/env python3
"""Multi-target TCP port scanner with exposure checking.

Scans hosts or networks for open TCP ports (full connect scan), optionally grabs
service banners, and can compare the result with an "expected ports" policy to
report unexpected exposure and expected services that are down.

Use it only on systems you own or are explicitly authorized to test.
"""

import argparse
import ipaddress
import json
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
             993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
HTTP_PORTS = {80, 8000, 8008, 8080, 8081}


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


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def scan_port(host, port, timeout):
    """Return True if the TCP port is open (completes the three-way handshake)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan(targets, ports, threads, timeout):
    """Scan every (host, port) pair with a pool of worker threads."""
    queue = Queue()
    for host in targets:
        for port in ports:
            queue.put((host, port))
    open_ports = {host: [] for host in targets}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                host, port = queue.get_nowait()
            except Empty:
                return
            if scan_port(host, port, timeout):
                with lock:
                    open_ports[host].append(port)

    pool = [threading.Thread(target=worker) for _ in range(min(threads, queue.qsize()))]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return {host: sorted(found) for host, found in open_ports.items()}


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


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
# Results
# --------------------------------------------------------------------------
def build_results(open_ports, scanned_ports, banners, expected_map):
    scanned = set(scanned_ports)
    hosts = []
    for host, found in open_ports.items():
        expected = None
        if expected_map is not None:
            expected = expected_map.get(host, expected_map.get("*"))
        entry = {
            "host": host,
            "open": [{"port": p, "service": service_name(p), "banner": banners.get((host, p), "")}
                     for p in found],
            "expected": sorted(expected) if expected is not None else None,
            "unexpected_open": [],
            "expected_closed": [],
        }
        if expected is not None:
            entry["unexpected_open"] = sorted(set(found) - expected)
            entry["expected_closed"] = sorted((expected & scanned) - set(found))
        hosts.append(entry)
    return hosts


def print_report(hosts, show_banner):
    for entry in hosts:
        print(f"\n{entry['host']}")
        if not entry["open"]:
            print("  no open ports found")
        else:
            header = f"  {'PORT':<7}{'SERVICE':<12}" + ("BANNER" if show_banner else "")
            print(header.rstrip())
            for item in entry["open"]:
                row = f"  {item['port']:<7}{item['service']:<12}"
                print((row + item["banner"]).rstrip() if show_banner else row.rstrip())
        if entry["unexpected_open"]:
            print(f"  [!] UNEXPECTED open: {', '.join(map(str, entry['unexpected_open']))}")
        if entry["expected_closed"]:
            print(f"  [!] EXPECTED but closed: {', '.join(map(str, entry['expected_closed']))}")


def main():
    parser = argparse.ArgumentParser(description="Multi-target TCP port scanner")
    parser.add_argument("targets", nargs="*", help="IPs, hostnames or CIDR networks (e.g. 10.0.0.0/28)")
    parser.add_argument("-iL", "--input-file", help="file with one target per line (# for comments)")
    parser.add_argument("-p", "--ports", type=parse_ports, default="1-1024",
                        help="ports: 22,80,443 | 1-1024 | top (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds per port (default: 1.0)")
    parser.add_argument("--banner", action="store_true", help="grab service banners from open ports")
    parser.add_argument("--expected", help="JSON file with the expected open ports per host")
    parser.add_argument("--vantage", default="", help="where the scan runs from, e.g. LAN or WAN (recorded in the output)")
    parser.add_argument("--json", dest="json_path", help="write the results to this JSON file")
    parser.add_argument("--max-hosts", type=int, default=256,
                        help="refuse to scan more hosts than this (default: 256)")
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

    where = f' from "{args.vantage}"' if args.vantage else ""
    print(f"Scanning {len(targets)} host(s), {len(args.ports)} port(s) each{where}...")
    started = datetime.now()
    clock = time.time()

    open_ports = scan(targets, args.ports, args.threads, args.timeout)

    banners = {}
    if args.banner:
        for host, found in open_ports.items():
            for port in found:
                banners[(host, port)] = grab_banner(host, port, args.timeout)

    duration = time.time() - clock
    hosts = build_results(open_ports, args.ports, banners, expected_map)
    print_report(hosts, args.banner)

    total_open = sum(len(h["open"]) for h in hosts)
    unexpected = sum(len(h["unexpected_open"]) for h in hosts)
    closed = sum(len(h["expected_closed"]) for h in hosts)
    print(f"\nDone in {duration:.2f}s: {total_open} open port(s) on {len(hosts)} host(s)", end="")
    print(f", {unexpected} unexpected, {closed} expected but closed" if expected_map is not None else "")

    if args.json_path:
        payload = {
            "scan": {"vantage": args.vantage, "started": started.isoformat(timespec="seconds"),
                     "duration_seconds": round(duration, 2), "ports_scanned": len(args.ports),
                     "targets": targets},
            "hosts": hosts,
        }
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Results written to {out}")

    if expected_map is not None and (unexpected or closed):
        sys.exit(1)


if __name__ == "__main__":
    main()