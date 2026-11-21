#!/usr/bin/env python3
"""Cisco IOS configuration security auditor (Standalone).

Reads backed-up running-configs (plaintext or age-encrypted), or connects
directly to devices via SSH using devices.json, checks them against
hardening rules, and writes JSON + Markdown reports.

Audit only configs of devices you own or are authorized to assess.
Secrets (passwords, community strings) are never copied into the reports.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Make console output UTF-8 so device names / error text never crash printing on Windows
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        NetmikoBaseException,
    )
except ImportError:
    ConnectHandler = None

SEVERITIES = ["High", "Medium", "Low"]
PHYSICAL = re.compile(r"^interface (Ethernet|FastEthernet|GigabitEthernet|TenGigabitEthernet)\S+")

SHOW_RUN_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_asa": "show running-config",
}


@dataclass
class Finding:
    device: str
    rule_id: str
    severity: str
    title: str
    fix: str
    evidence: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def parse_config(text):
    """Split a running-config into top-level lines and (header, children) blocks."""
    top, blocks, current = [], [], None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("!"):
            current = None
            continue
        if raw[0] in " \t":
            if current is not None:
                current[1].append(stripped)
        else:
            top.append(stripped)
            current = (stripped, [])
            blocks.append(current)
    return top, blocks


class Config:
    def __init__(self, text):
        self.top, self.blocks = parse_config(text)
        # A device is treated as a switch if it has any L2 configuration.
        self.is_switch = self.has(r"^spanning-tree mode") or any(
            c.startswith("switchport") for _, children in self.blocks for c in children
        )

    def has(self, pattern):
        return any(re.search(pattern, line) for line in self.top)

    def find(self, pattern):
        return [line for line in self.top if re.search(pattern, line)]

    def vty_lines(self):
        return [(h, ch) for h, ch in self.blocks if h.startswith("line vty")]

    def l2_ports(self):
        """Physical L2 ports that are up (not shutdown, not routed)."""
        if not self.is_switch:
            return []
        return [
            (header.split(" ", 1)[1], children)
            for header, children in self.blocks
            if PHYSICAL.match(header) and "shutdown" not in children and "no switchport" not in children
        ]

    def access_ports(self):
        return [(n, ch) for n, ch in self.l2_ports() if "switchport mode access" in ch]


# --------------------------------------------------------------------------
# Rules: each check returns a list of evidence strings (empty list = pass)
# --------------------------------------------------------------------------
RULES = []


def rule(rule_id, severity, title, fix):
    def register(fn):
        RULES.append((rule_id, severity, title, fix, fn))
        return fn
    return register


# ---- Management plane ----
@rule("MGT-01", "High", "Telnet allowed on VTY lines",
      "Under 'line vty' set 'transport input ssh'.")
def vty_telnet(cfg):
    bad = []
    for header, children in cfg.vty_lines():
        transport = [c for c in children if c.startswith("transport input")]
        if not transport:
            bad.append(f"{header}: no 'transport input' set (default allows telnet)")
        elif re.search(r"\b(telnet|all)\b", transport[0]):
            bad.append(f"{header}: {transport[0]}")
    return bad


@rule("MGT-02", "Medium", "SSH version 2 not enforced", "Configure 'ip ssh version 2'.")
def ssh_v2(cfg):
    return [] if cfg.has(r"^ip ssh version 2") else ["'ip ssh version 2' not configured"]


@rule("MGT-03", "Medium", "VTY lines not restricted by an ACL",
      "Create a management ACL and apply it with 'access-class <acl> in' under 'line vty'.")
def vty_acl(cfg):
    return [f"{h}: no 'access-class'" for h, ch in cfg.vty_lines()
            if not any(c.startswith("access-class") for c in ch)]


@rule("MGT-04", "Medium", "Console/VTY sessions never time out",
      "Set 'exec-timeout 10 0' (or lower) under 'line con 0' and 'line vty'.")
def exec_timeout(cfg):
    return [f"{h}: exec-timeout 0 0" for h, ch in cfg.blocks
            if h.startswith(("line con", "line vty")) and "exec-timeout 0 0" in ch]


@rule("MGT-05", "Medium", "HTTP server enabled", "Disable with 'no ip http server'.")
def http_server(cfg):
    return ["'ip http server' is enabled"] if cfg.has(r"^ip http server") else []


@rule("MGT-06", "Medium", "AAA not enabled", "Enable 'aaa new-model' and configure AAA (TACACS+/RADIUS or local).")
def aaa(cfg):
    return [] if cfg.has(r"^aaa new-model") else ["'aaa new-model' not configured"]


# ---- Credentials ----
@rule("PWD-01", "High", "Privileged EXEC not protected by a strong 'enable secret'",
      "Use 'enable secret' (type 8/9) and remove 'enable password'.")
def enable_secret(cfg):
    bad = []
    if not cfg.has(r"^enable secret"):
        bad.append("'enable secret' not configured")
    if cfg.has(r"^enable password"):
        bad.append("'enable password' configured (weak or reversible protection)")
    return bad


@rule("PWD-02", "Low", "Password encryption service disabled",
      "Configure 'service password-encryption' (obscures type 0 passwords in the config).")
def password_encryption(cfg):
    return [] if cfg.has(r"^service password-encryption") else ["'service password-encryption' not configured"]


@rule("PWD-03", "Medium", "Local users defined with 'password' instead of 'secret'",
      "Recreate users with 'username <name> privilege <n> secret <password>'.")
def local_users(cfg):
    out = []
    for line in cfg.top:
        m = re.match(r"username (\S+) (?:privilege \d+ )?password", line)
        if m:
            out.append(f"user '{m.group(1)}' uses 'password' instead of 'secret'")
    return out


@rule("SNMP-01", "High", "Default or read-write SNMP community strings",
      "Remove public/private; prefer SNMPv3 (authPriv), or a strong RO community restricted by ACL.")
def snmp_communities(cfg):
    bad = []
    for line in cfg.find(r"^snmp-server community"):
        parts = line.split()
        name = parts[2] if len(parts) > 2 else ""
        mode = next((p.upper() for p in parts[3:] if p.upper() in ("RO", "RW")), "RO")
        default = name.lower() in ("public", "private")
        if default or mode == "RW":
            shown = name if default else "<hidden>"
            bad.append(f"community '{shown}' ({mode})")
    return bad


# ---- Services / visibility ----
@rule("SVC-01", "Low", "CDP enabled globally (reconnaissance risk)",
      "Disable with 'no cdp run', or disable per-interface on untrusted ports.")
def cdp(cfg):
    return [] if cfg.has(r"^no cdp run") else ["CDP is enabled globally"]


@rule("LOG-01", "Low", "No remote logging configured", "Configure 'logging host <syslog-ip>'.")
def remote_logging(cfg):
    return [] if cfg.has(r"^logging (host )?\d") else ["no 'logging host' configured"]


@rule("BAN-01", "Low", "No login/MOTD banner", "Configure 'banner motd' with an authorized-access warning.")
def banner(cfg):
    return [] if cfg.has(r"^banner (motd|login)") else ["no banner configured"]


# ---- Layer 2 (switches only) ----
@rule("L2-01", "Medium", "DHCP snooping not enabled (rogue DHCP risk)",
      "Configure 'ip dhcp snooping' and 'ip dhcp snooping vlan <ids>'; trust only uplinks.")
def dhcp_snooping(cfg):
    if cfg.is_switch and not cfg.has(r"^ip dhcp snooping vlan"):
        return ["'ip dhcp snooping vlan' not configured"]
    return []


@rule("L2-02", "Medium", "Dynamic ARP Inspection not enabled (ARP spoofing risk)",
      "Configure 'ip arp inspection vlan <ids>' (requires DHCP snooping bindings).")
def dai(cfg):
    if cfg.is_switch and not cfg.has(r"^ip arp inspection vlan"):
        return ["'ip arp inspection vlan' not configured"]
    return []


@rule("L2-03", "Medium", "Access ports without port security (CAM overflow risk)",
      "Under each access port: 'switchport port-security' with a sensible maximum and violation mode.")
def port_security(cfg):
    return [f"{n}: port-security not enabled" for n, ch in cfg.access_ports()
            if not any(c.startswith("switchport port-security") for c in ch)]


@rule("L2-04", "Medium", "Access ports without BPDU Guard (STP manipulation risk)",
      "Use 'spanning-tree portfast bpduguard default' or 'spanning-tree bpduguard enable' per port.")
def bpdu_guard(cfg):
    if cfg.has(r"^spanning-tree portfast bpduguard default"):
        return []
    return [f"{n}: BPDU Guard not enabled" for n, ch in cfg.access_ports()
            if "spanning-tree bpduguard enable" not in ch]


@rule("L2-05", "Medium", "Ports left in dynamic trunking mode (VLAN hopping risk)",
      "Set 'switchport mode access' (or 'trunk' with 'switchport nonegotiate') on every port.")
def dynamic_ports(cfg):
    return [f"{n}: no fixed 'switchport mode' (DTP active)" for n, ch in cfg.l2_ports()
            if "switchport mode access" not in ch and "switchport mode trunk" not in ch]


@rule("L2-06", "Medium", "Trunks use the default native VLAN 1",
      "Set 'switchport trunk native vlan <unused-id>' on trunks.")
def trunk_native(cfg):
    bad = []
    for n, ch in cfg.l2_ports():
        if "switchport mode trunk" in ch:
            native = [c for c in ch if c.startswith("switchport trunk native vlan")]
            if not native or native[0].split()[-1] == "1":
                bad.append(f"{n}: native VLAN is 1")
    return bad


# --------------------------------------------------------------------------
# Crypto (age) & Live SSH Helpers
# --------------------------------------------------------------------------
def decrypt_age_in_memory(filepath: Path, identity_path: str | None) -> str:
    """Decrypt an .age file in memory using age CLI without writing plaintext to disk."""
    identity = identity_path or os.environ.get("AGE_IDENTITY")
    if not identity:
        raise ValueError("AGE_IDENTITY env var not set and --identity not provided")
    proc = subprocess.run(
        ["age", "-d", "-i", identity, str(filepath)],
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode("utf-8", errors="replace")


def build_connection_params(device: dict) -> dict:
    """Build Netmiko connection parameters (supports env vars and SSH keys)."""
    params = {
        "host": device["host"],
        "username": device["username"],
        "device_type": device.get("device_type", "cisco_ios"),
    }

    password = device.get("password")
    if device.get("password_env"):
        password = os.environ.get(device["password_env"])
    if password:
        params["password"] = password

    if device.get("key_file"):
        params["use_keys"] = True
        params["key_file"] = os.path.expanduser(device["key_file"])

    if "password" not in params and "key_file" not in params:
        raise ValueError("neither a password nor a key_file is available")

    secret = device.get("secret")
    if device.get("secret_env"):
        secret = os.environ.get(device["secret_env"])
    if secret:
        params["secret"] = secret

    return params


def fetch_live_configs(devices_file: Path) -> dict[str, tuple[str, str]]:
    """Connect directly to devices in devices.json via SSH and fetch running-configs."""
    if ConnectHandler is None:
        sys.exit("Netmiko is required for --live mode. Install it with: pip install netmiko")

    try:
        devices = json.loads(devices_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"Invalid JSON in {devices_file}: {e}")

    if not isinstance(devices, list) or not devices:
        sys.exit(f"Devices file {devices_file} is empty or not a list.")

    live_data = {}
    for dev in devices:
        host = dev.get("host", "unknown")
        device_type = dev.get("device_type", "cisco_ios")
        command = SHOW_RUN_COMMANDS.get(device_type, "show running-config")

        try:
            params = build_connection_params(dev)
            print(f"[*] Connecting to {host} ({device_type}) via SSH...")
            with ConnectHandler(**params) as conn:
                if params.get("secret"):
                    conn.enable()

                if dev.get("name"):
                    name = dev["name"]
                else:
                    prompt = conn.find_prompt().strip()
                    name = re.sub(r"\(.*?\)", "", prompt).strip("#>$ ")

                output = conn.send_command(command, read_timeout=60)
                if output and output.strip():
                    live_data[name or host] = (f"ssh://{host}", output)
                else:
                    print(f"[!] {host}: returned empty config, skipped")
        except NetmikoAuthenticationException:
            print(f"[!] {host}: authentication failed, skipped")
        except NetmikoTimeoutException:
            print(f"[!] {host}: connection timed out, skipped")
        except (NetmikoBaseException, OSError, KeyError, ValueError) as e:
            print(f"[!] {host}: failed ({e}), skipped")

    return live_data


# --------------------------------------------------------------------------
# Audit engine
# --------------------------------------------------------------------------
def audit(device, text):
    cfg = Config(text)
    findings = []
    for rule_id, severity, title, fix, check in RULES:
        evidence = check(cfg)
        if evidence:
            findings.append(Finding(device, rule_id, severity, title, fix, evidence))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.rule_id))
    return findings


def latest_configs(path):
    """Map device name -> newest config file (one subfolder per device)."""
    if path.is_file():
        return {path.stem: path}
    configs = {}
    for folder in sorted(p for p in path.iterdir() if p.is_dir()):
        files = [f for f in folder.rglob("*") if f.is_file()]
        if files:
            configs[folder.name] = max(files, key=lambda f: f.stat().st_mtime)
    if not configs:  # flat folder: treat every file as a device
        configs = {f.stem: f for f in sorted(path.iterdir()) if f.is_file()}
    return configs


def summary(findings):
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_console(results):
    for device, info in results.items():
        counts = summary(info["findings"])
        print(f"\n=== {device}  (High {counts['High']} | Medium {counts['Medium']} | Low {counts['Low']})")
        print(f"    source: {info['source']}")
        if not info["findings"]:
            print("    no findings")
        for f in info["findings"]:
            print(f"  [{f.severity.upper():<6}] {f.rule_id}  {f.title}")
            for ev in f.evidence[:5]:
                print(f"           - {ev}")
            if len(f.evidence) > 5:
                print(f"           - ... and {len(f.evidence) - 5} more")


def write_reports(results, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    # صيغة تاريخ ووقت واضحة ومرتبة زمنياً
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = out_dir / f"audit_{stamp}.json"
    md_path = out_dir / f"audit_{stamp}.md"

    payload = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "devices": [
            {"device": d, "source": i["source"], "summary": summary(i["findings"]),
             "findings": [asdict(f) for f in i["findings"]]}
            for d, i in results.items()
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = ["# Config Security Audit", "", f"Generated: {payload['generated']}", "",
             "| Device | High | Medium | Low |", "|---|---|---|---|"]
    for d, i in results.items():
        c = summary(i["findings"])
        lines.append(f"| {d} | {c['High']} | {c['Medium']} | {c['Low']} |")
    for d, i in results.items():
        lines += ["", f"## {d}", "", f"Source: `{i['source']}`", ""]
        if not i["findings"]:
            lines.append("No findings.")
        for f in i["findings"]:
            lines.append(f"### [{f.severity}] {f.rule_id}: {f.title}")
            lines += [f"- Evidence: {ev}" for ev in f.evidence]
            lines += [f"- Fix: {f.fix}", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path, stamp


def _extract_findings_signature(json_file: Path) -> list:
    """استخراج بيانات الثغرات فقط من ملف JSON للمقارنة بدون التاريخ والوقت."""
    data = json.loads(json_file.read_text(encoding="utf-8"))
    # نستخرج لكل جهاز: اسمه + ملخص الثغرات + قائمة الثغرات نفسها
    return [
        {
            "device": d.get("device"),
            "summary": d.get("summary"),
            "findings": d.get("findings"),
        }
        for d in data.get("devices", [])
    ]


def save_evidence_snapshot(results, json_path: Path, md_path: Path, stamp: str, evidence_dir: Path):
    """
    - BEFORE: يتحفظ مرة واحدة عند أول ظهور للثغرات.
    - AFTER: يتحفظ كل ما النتيجة تختلف عن BEFORE وعن آخر AFTER.
    """
    total_findings = sum(len(i["findings"]) for i in results.values())
    before_dir = evidence_dir / "before"
    after_dir = evidence_dir / "after"

    before_jsons = sorted(before_dir.rglob("*.json")) if before_dir.exists() else []
    after_jsons = sorted(after_dir.rglob("*.json")) if after_dir.exists() else []

    def _save(base_dir: Path, label: str):
        target = base_dir / stamp
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy2(json_path, target / json_path.name)
        shutil.copy2(md_path, target / md_path.name)
        print(f"[+] Evidence saved ({label}): {target}")

    # 1. مفيش BEFORE لسه
    if not before_jsons:
        if total_findings > 0:
            _save(before_dir, "BEFORE hardening")
        return

    current_sig = _extract_findings_signature(json_path)

    # 2. نفس حالة BEFORE -> مفيش تغيير
    if current_sig == _extract_findings_signature(before_jsons[-1]):
        print("[=] No changes detected compared to BEFORE evidence; skipping AFTER snapshot.")
        return

    # 3. نفس حالة آخر AFTER -> متكررش
    if after_jsons and current_sig == _extract_findings_signature(after_jsons[-1]):
        print("[=] Results identical to the latest AFTER snapshot; skipping.")
        return

    # 4. فيه تغيير جديد -> احفظ AFTER جديد (القديم بيفضل زي ما هو)
    _save(after_dir, "AFTER hardening")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    project_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Cisco IOS config security auditor")
    parser.add_argument("path", type=Path,
                        help="backup folder, single config file, or devices.json (with --live)")
    parser.add_argument("--live", action="store_true",
                        help="connect directly to devices in devices.json via SSH")
    parser.add_argument("--identity", type=str, default=None,
                        help="path to age identity (private key) file to decrypt .cfg.age files")
    parser.add_argument("--fail-on", choices=SEVERITIES,
                        help="exit with code 1 if a finding of this severity or higher exists")
    parser.add_argument("--out-dir", type=Path, default=project_root / "reports",
                        help="where to write JSON/Markdown reports (default: reports)")
    parser.add_argument("--evidence-dir", type=Path, default=project_root / "evidence",
                        help="where to save one-time before/after evidence snapshots (default: evidence)")
    args = parser.parse_args()

    if not args.path.exists():
        sys.exit(f"Path not found: {args.path}")

    results = {}

    if args.live:
        for device, (source, text) in fetch_live_configs(args.path).items():
            if not re.search(r"^(hostname|version) ", text, re.M):
                print(f"[!] {device}: output from {source} does not look like an IOS config, skipped")
                continue
            results[device] = {"source": source, "findings": audit(device, text)}
    else:
        for device, file in latest_configs(args.path).items():
            if file.suffix == ".age":
                try:
                    text = decrypt_age_in_memory(file, args.identity)
                except ValueError as e:
                    print(f"[!] {device}: {file.name} is encrypted ({e}), skipped")
                    continue
                except subprocess.CalledProcessError as e:
                    err = (e.stderr or b"").decode(errors="ignore").strip()
                    print(f"[!] {device}: failed to decrypt {file.name} ({err}), skipped")
                    continue
                except FileNotFoundError:
                    print(f"[!] {device}: 'age' CLI not found in PATH to decrypt {file.name}, skipped")
                    continue
            else:
                text = file.read_text(encoding="utf-8", errors="replace")

            if not re.search(r"^(hostname|version) ", text, re.M):
                print(f"[!] {device}: {file.name} does not look like an IOS config "
                      "(encrypted or empty?), skipped")
                continue
            results[device] = {"source": str(file), "findings": audit(device, text)}

    if not results:
        sys.exit("No readable configs found.")

    print_console(results)
    json_path, md_path, stamp = write_reports(results, args.out_dir)
    print(f"\nReports: {json_path}  |  {md_path}")

    save_evidence_snapshot(results, json_path, md_path, stamp, args.evidence_dir)



    if args.fail_on:
        limit = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= limit for i in results.values() for f in i["findings"]):
            sys.exit(1)


if __name__ == "__main__":
    main()