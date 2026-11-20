#!/usr/bin/env python3
"""
Config Backup Tool - NOC Automation (v4, cross-platform, with alerts)
=====================================================================
- Reads the list of network devices you maintain manually in devices.json
- Pulls the running-config from every device (in parallel)
- Saves each device's backups in its own folder:
      backups/<device_name>/<device_name>_<timestamp>.cfg.age
- Encrypts every config with age (public-key encryption) before it touches disk
- Deletes backups older than N days (default 15), but always keeps the newest
  backup of every device
- Can run automatically every day at a fixed time (--schedule HH:MM)
- Optional git commit/push (--push)
- NEW (phase 3) Alerts after every cycle:
    * Telegram : one summary message (OK or FAILED, with the failed devices)
    * Zabbix   : per-device result sent with zabbix_sender to trapper items

Works on Linux and Windows.

Usage examples:
    python Config_Backup_Tool.py                      # run once, now
    python Config_Backup_Tool.py --schedule 02:00     # stay alive, back up daily at 02:00
    python Config_Backup_Tool.py --retention-days 15  # (default is 15)
    python Config_Backup_Tool.py --push               # also git commit + push
    python Config_Backup_Tool.py --alert-only-failures  # Telegram only when something fails
    python Config_Backup_Tool.py --no-alerts          # disable Telegram + Zabbix

Recommended scheduling:
    Linux   : systemd service or cron (run without --schedule)
    Windows : Task Scheduler (run without --schedule), for example:
        schtasks /Create /TN "ConfigBackup" /SC DAILY /ST 02:00 /F /TR
            "\"C:\\config-backup\\venv\\Scripts\\python.exe\" \"C:\\config-backup\\Config_Backup_Tool.py\""

Requirements:
    pip install netmiko
    age (https://github.com/FiloSottile/age) available in PATH
    AGE_RECIPIENT environment variable set to your age PUBLIC key (age1...)

Alert settings (all via environment variables, never in the code):
    TELEGRAM_BOT_TOKEN   bot token from @BotFather
    TELEGRAM_CHAT_ID     chat/user id that receives the alerts
    ZABBIX_SERVER        IP/DNS of the Zabbix server or proxy (enables Zabbix alerts)
    ZABBIX_PORT          optional, default 10051
    ZABBIX_SENDER        optional full path to zabbix_sender(.exe) if it is not in PATH
  Windows (then open a NEW terminal):
    setx TELEGRAM_BOT_TOKEN "123456:ABC..."
    setx TELEGRAM_CHAT_ID "123456789"
    setx ZABBIX_SERVER "192.168.100.10"
  An alert channel whose variables are not set is simply skipped.

Zabbix side (per device host, host name must match the device name exactly,
or set "zabbix_host" in devices.json):
    item 1: key config.backup.status   type Zabbix trapper, Numeric (unsigned)  0 = OK, 1 = FAILED
    item 2: key config.backup.message  type Zabbix trapper, Text
    trigger: last(/HOST/config.backup.status)=1
    trigger: nodata(/HOST/config.backup.status,26h)=1   (script did not run at all)
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Make console output UTF-8 so device names / error text never crash printing
# (the default Windows console encoding is often cp1252 or cp437).
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
    print("Netmiko is not installed. Install it with: pip install netmiko")
    sys.exit(1)

# ----------------------------------------------------------------------------
# Global settings
# ----------------------------------------------------------------------------
IS_WINDOWS = os.name == "nt"

BASE_DIR = Path(__file__).resolve().parent
BACKUP_DIR = BASE_DIR / "backups"
LOG_FILE = BASE_DIR / "backup.log"
DEVICES_FILE = BASE_DIR / "devices.json"

DEFAULT_RETENTION_DAYS = 15

# age PUBLIC key (starts with age1...). The private key must stay offline.
AGE_RECIPIENT = os.environ.get("AGE_RECIPIENT")

# Alert settings (environment variables only - never hard-code secrets)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
ZABBIX_SERVER = os.environ.get("ZABBIX_SERVER")
ZABBIX_PORT = os.environ.get("ZABBIX_PORT", "10051")
ZABBIX_SENDER = os.environ.get("ZABBIX_SENDER") or shutil.which("zabbix_sender")
ZABBIX_STATUS_KEY = "config.backup.status"    # 0 = OK, 1 = FAILED
ZABBIX_MESSAGE_KEY = "config.backup.message"  # text: saved file or error

# Command used to fetch the config for each device type (add more as needed)
SHOW_RUN_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_asa": "show running-config",
    "juniper_junos": "show configuration | display set",
    "arista_eos": "show running-config",
    "huawei": "display current-configuration",
    "fortinet": "show full-configuration",
}

# Backup file name pattern: <name>_YYYYMMDD_HHMMSS.cfg  or  .cfg.age
FILE_RE = re.compile(r"_(\d{8}_\d{6})\.cfg(\.age)?$")

# Names Windows refuses to use for files/folders (applied on every OS so that
# backups are portable between systems)
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

file_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[file_handler, logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("config_backup")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def safe_name(name: str) -> str:
    """Convert a device name into a safe folder/file name (valid on Windows and Linux)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name.strip()).strip(". ")
    if not cleaned:
        return "unknown"
    if cleaned.split(".")[0].upper() in WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}"
    return cleaned


def restrict_permissions(path: Path, mode: int) -> None:
    """
    Restrict permissions on POSIX systems (chmod 600 / 700).
    On Windows chmod has no real effect; the backup root is locked down with
    icacls instead (see lock_down_windows_dir).
    """
    if IS_WINDOWS:
        return
    try:
        path.chmod(mode)
    except OSError as e:
        logger.warning(f"Could not set permissions on {path}: {e}")


def lock_down_windows_dir(path: Path) -> None:
    """
    Windows only: give the current user exclusive access to a folder using icacls.
    Child files and folders inherit these permissions.
    Note: this removes inherited permissions (e.g. SYSTEM/Administrators). If the
    scheduled task runs under a different account, use --no-acl and set ACLs yourself.
    """
    user = os.environ.get("USERNAME")
    if not user:
        logger.warning("USERNAME is not set; skipping Windows ACL hardening.")
        return
    domain = os.environ.get("USERDOMAIN")
    account = f"{domain}\\{user}" if domain else user
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:(OI)(CI)F"],
            capture_output=True,
            check=True,
        )
        logger.info(f"Restricted {path} to {account} only.")
    except (subprocess.CalledProcessError, OSError) as e:
        logger.warning(f"Could not apply Windows ACLs to {path}: {e}")


def load_devices(devices_file: Path) -> list:
    """
    Read the devices JSON file. Each device looks like this:
    {
        "name": "MSW",            // optional: folder name (otherwise taken from the device prompt)
        "zabbix_host": "Multi-Layer Switch",     // optional: host name in Zabbix (defaults to "name")
        "host": "192.168.100.3",
        "username": "admin",
        "password_env": "MSW_PASS",             // or "password_env": "NAME_OF_ENV_VAR"
        "device_type": "cisco_ios",
        "secret": "enable_password",   // optional (or "secret_env")
        "key_file": "/path/to/key"     // optional: SSH key instead of a password
    }
    On Windows, write paths with forward slashes or doubled backslashes,
    e.g. "C:/Users/me/.ssh/id_ed25519".
    """
    if not devices_file.exists():
        logger.error(f"Devices file not found: {devices_file}")
        sys.exit(1)

    try:
        with open(devices_file, "r", encoding="utf-8") as f:
            devices = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Devices file contains invalid JSON: {e}")
        sys.exit(1)

    if not isinstance(devices, list) or not devices:
        logger.error("Devices file is empty or is not a list.")
        sys.exit(1)

    return devices


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


def encrypt_and_save(output: str, filepath: Path, encrypt: bool) -> Path:
    """
    Save the config. When encrypt=True the text is piped to age through stdin,
    so a plaintext copy is never written to disk.
    """
    if encrypt:
        if not AGE_RECIPIENT:
            raise ValueError("AGE_RECIPIENT is not set")
        final_path = filepath.with_name(filepath.name + ".age")
        subprocess.run(
            ["age", "-r", AGE_RECIPIENT, "-o", str(final_path)],
            input=output.encode("utf-8"),
            capture_output=True,
            check=True,
        )
    else:
        final_path = filepath
        # newline="\n" keeps line endings identical on Windows and Linux
        with open(final_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(output)

    restrict_permissions(final_path, 0o600)
    return final_path


# ----------------------------------------------------------------------------
# Back up a single device
# ----------------------------------------------------------------------------
def backup_device(device: dict, encrypt: bool) -> dict:
    host = device.get("host", "unknown")
    device_type = device.get("device_type", "cisco_ios")
    command = SHOW_RUN_COMMANDS.get(device_type, "show running-config")

    result = {
        "host": host,
        # "name" is what alerts show; it is refined below once the real hostname is known
        "name": safe_name(device.get("name") or host),
        "zabbix_host": device.get("zabbix_host"),
        "success": False,
        "filename": None,
        "error": None,
    }

    try:
        params = build_connection_params(device)
        logger.info(f"Connecting to {host} ({device_type})...")

        with ConnectHandler(**params) as conn:
            if params.get("secret"):
                conn.enable()

            # Device name: from devices.json if present, otherwise from the CLI prompt
            if device.get("name"):
                hostname = device["name"]
            else:
                try:
                    prompt = conn.find_prompt().strip()
                    hostname = re.sub(r"\(.*?\)", "", prompt).strip("#>$ ")
                    if "@" in hostname:  # Juniper prompt: user@host
                        hostname = hostname.split("@", 1)[1]
                except (NetmikoBaseException, OSError, ValueError):
                    hostname = host
            hostname = safe_name(hostname or host)
            result["name"] = hostname

            output = conn.send_command(command, read_timeout=60)

        if not output or not output.strip():
            raise ValueError("the device returned an empty config")

        # One dedicated folder per device
        device_dir = BACKUP_DIR / hostname
        device_dir.mkdir(parents=True, exist_ok=True)
        restrict_permissions(device_dir, 0o700)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = device_dir / f"{hostname}_{timestamp}.cfg"
        saved = encrypt_and_save(output, filepath, encrypt)

        logger.info(f"Saved config of {host} to: {saved.relative_to(BASE_DIR)}")
        result["success"] = True
        result["filename"] = str(saved.relative_to(BASE_DIR))

    except NetmikoAuthenticationException:
        result["error"] = f"Authentication failed on {host} (wrong username/password or key)"
    except NetmikoTimeoutException:
        result["error"] = f"No response from {host} (timeout)"
    except NetmikoBaseException as e:
        result["error"] = f"Netmiko error on {host}: {e}"
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="ignore").strip()
        result["error"] = f"age encryption failed for {host}: {stderr}"
    except FileNotFoundError as e:
        result["error"] = f"File or executable not found while backing up {host}: {e}"
    except OSError as e:
        result["error"] = f"Network/file error on {host}: {e}"
    except (KeyError, ValueError) as e:
        result["error"] = f"Device entry for {host} is incomplete or invalid: {e}"

    if result["error"]:
        logger.error(result["error"])
    return result


def backup_all_devices(devices: list, encrypt: bool, max_workers: int = 5) -> list:
    """Back up all devices in parallel."""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(backup_device, d, encrypt) for d in devices]
        for future in as_completed(futures):
            results.append(future.result())
    return results


# ----------------------------------------------------------------------------
# Retention: delete backups older than N days
# ----------------------------------------------------------------------------
def file_timestamp(path: Path) -> datetime:
    """Get the backup time from the file name (more reliable than mtime); fall back to mtime."""
    m = FILE_RE.search(path.name)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
        except ValueError:
            pass
    return datetime.fromtimestamp(path.stat().st_mtime)


def cleanup_old_backups(retention_days: int) -> int:
    """
    Delete every backup older than retention_days.
    Safety: the newest backup of each device is always kept, even if it is older
    than the retention period, so a device that stopped responding never loses
    its last known config.
    """
    if not BACKUP_DIR.exists():
        return 0

    cutoff = datetime.now() - timedelta(days=retention_days)
    deleted = 0

    for device_dir in BACKUP_DIR.iterdir():
        if not device_dir.is_dir():
            continue
        files = [p for p in device_dir.iterdir() if p.is_file() and FILE_RE.search(p.name)]
        if len(files) <= 1:
            continue

        files.sort(key=file_timestamp)  # oldest -> newest
        newest = files[-1]
        for p in files:
            if p == newest:
                continue
            if file_timestamp(p) < cutoff:
                try:
                    p.unlink()
                    deleted += 1
                    logger.info(f"Deleted old backup: {p.relative_to(BASE_DIR)}")
                except OSError as e:
                    logger.error(f"Failed to delete {p}: {e}")

    logger.info(f"Retention: deleted {deleted} file(s) older than {retention_days} day(s)")
    return deleted


# ----------------------------------------------------------------------------
# Alerts: Telegram + Zabbix
# ----------------------------------------------------------------------------
def send_telegram(text: str) -> bool:
    """
    Send a message through the Telegram Bot API (plain HTTPS POST).
    The token comes from the environment and is never logged: the URL contains
    it, so error messages only show the exception type / HTTP code.
    """
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        logger.info("Telegram not configured (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID); skipping.")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": TELEGRAM_CHAT_ID, "text": text[:4000]}  # Telegram limit is 4096 chars
    ).encode("utf-8")
    try:
        with urllib.request.urlopen(url, data=data, timeout=15) as resp:
            ok = resp.status == 200
    except urllib.error.HTTPError as e:
        logger.error(f"Telegram alert failed: HTTP {e.code}")
        return False
    except (urllib.error.URLError, OSError) as e:
        logger.error(f"Telegram alert failed: {type(e).__name__}")
        return False

    if ok:
        logger.info("Telegram alert sent.")
    return ok


def _zabbix_quote(value) -> str:
    """Quote a field for the zabbix_sender input file (single line, no inner quotes/backslashes)."""
    text = " ".join(str(value).split())            # collapse newlines and extra whitespace
    text = text.replace("\\", "/").replace('"', "'")
    return f'"{text}"'


def send_zabbix(results: list) -> bool:
    """
    Send every device result to Zabbix trapper items with ONE zabbix_sender call
    (input read from stdin). For each device:
        config.backup.status   0 = OK, 1 = FAILED
        config.backup.message  saved file name or the error text
    The host name in Zabbix must match r["zabbix_host"] (or the device name).
    """
    if not ZABBIX_SERVER:
        logger.info("Zabbix not configured (ZABBIX_SERVER); skipping.")
        return False
    if not ZABBIX_SENDER:
        logger.warning("zabbix_sender was not found in PATH (or set ZABBIX_SENDER); skipping Zabbix.")
        return False

    lines = []
    for r in results:
        zhost = _zabbix_quote(r.get("zabbix_host") or r["name"])
        status = 0 if r["success"] else 1
        message = (r["filename"] if r["success"] else r["error"]) or ""
        lines.append(f"{zhost} {ZABBIX_STATUS_KEY} {status}")
        lines.append(f"{zhost} {ZABBIX_MESSAGE_KEY} {_zabbix_quote(message[:250])}")

    cmd = [ZABBIX_SENDER, "-z", ZABBIX_SERVER, "-p", str(ZABBIX_PORT), "-i", "-"]
    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.error(f"zabbix_sender failed to run: {type(e).__name__}")
        return False

    summary = (proc.stdout or proc.stderr or "").strip().splitlines()
    summary_line = next((l for l in reversed(summary) if "processed:" in l), "")
    if proc.returncode == 0:
        logger.info(f"Zabbix: {summary_line or 'data sent'}")
        return True

    # Return code 2 = some values failed (e.g. host/item does not exist in Zabbix)
    logger.error(f"Zabbix: sender returned {proc.returncode}. {summary_line or ' | '.join(summary[-3:])}")
    return False


def build_alert_text(results: list, deleted: int, retention_days: int) -> str:
    failed = [r for r in results if not r["success"]]
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    if failed:
        lines = [f"❌ Config backup: {len(failed)}/{len(results)} FAILED ({now})"]
        for r in failed:
            lines.append(f"- {r['name']} ({r['host']}): {r['error']}")
        ok_names = [r["name"] for r in results if r["success"]]
        if ok_names:
            lines.append("OK: " + ", ".join(sorted(ok_names)))
    else:
        lines = [f"✅ Config backup OK: {len(results)}/{len(results)} devices ({now})"]
    lines.append(f"Retention: removed {deleted} file(s) older than {retention_days} days")
    return "\n".join(lines)


def send_alerts(results: list, deleted: int, args) -> None:
    """Send results to Zabbix and Telegram. An alert problem never breaks the backup."""
    if args.no_alerts:
        return
    try:
        send_zabbix(results)
        has_failures = any(not r["success"] for r in results)
        if has_failures or not args.alert_only_failures:
            send_telegram(build_alert_text(results, deleted, args.retention_days))
    except Exception:
        logger.exception("Unexpected error while sending alerts")


# ----------------------------------------------------------------------------
# Git (optional)
# ----------------------------------------------------------------------------
def run_git_command(args: list, cwd: Path) -> tuple:
    """Run a git command and return (success, output)."""
    try:
        proc = subprocess.run(
            ["git"] + args, cwd=cwd, capture_output=True, text=True, check=True
        )
        return True, proc.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or e.stdout).strip()
    except FileNotFoundError:
        return False, "git is not installed or not in PATH"


def git_commit_and_push(results: list, branch: str) -> None:
    success_count = sum(1 for r in results if r["success"])
    fail_count = len(results) - success_count

    # -A so files removed by the retention policy are recorded as well
    ok, out = run_git_command(["add", "-A", str(BACKUP_DIR)], BASE_DIR)
    if not ok:
        logger.error(f"git add failed: {out}")
        return

    ok, out = run_git_command(["status", "--porcelain", str(BACKUP_DIR)], BASE_DIR)
    if ok and not out:
        logger.info("No changes to commit.")
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"Config backup: {success_count} succeeded, {fail_count} failed - {ts}"
    ok, out = run_git_command(["commit", "-m", msg], BASE_DIR)
    if not ok:
        logger.error(f"git commit failed: {out}")
        return
    logger.info(f"Committed: {msg}")

    ok, out = run_git_command(["push", "origin", branch], BASE_DIR)
    if ok:
        logger.info("git push succeeded.")
    else:
        logger.error(f"git push failed: {out}")


# ----------------------------------------------------------------------------
# One full backup cycle
# ----------------------------------------------------------------------------
def _run_backup_cycle(args) -> None:
    logger.info("=" * 60)
    logger.info("Starting config backup")

    devices = load_devices(Path(args.devices))
    logger.info(f"Backing up {len(devices)} device(s)")

    results = backup_all_devices(devices, encrypt=not args.no_encrypt, max_workers=args.workers)

    failed = [r for r in results if not r["success"]]
    logger.info(f"Result: {len(results) - len(failed)} succeeded / {len(failed)} failed")
    for r in failed:
        logger.warning(f"  Failed: {r['host']} - {r['error']}")

    deleted = cleanup_old_backups(args.retention_days)

    # Alerts go out before git so a push problem can never swallow them
    send_alerts(results, deleted, args)

    if args.push:
        git_commit_and_push(results, args.branch)

    logger.info("Backup cycle finished.")
    logger.info("=" * 60)


def run_backup_cycle(args) -> None:
    """
    Run one cycle. If the whole cycle aborts (bad devices.json, unexpected error)
    a Telegram alert is sent, then the error is re-raised as before.
    """
    try:
        _run_backup_cycle(args)
    except (Exception, SystemExit):
        if not args.no_alerts:
            send_telegram(
                f"❌ Config backup cycle ABORTED ({datetime.now():%Y-%m-%d %H:%M}). "
                "Check backup.log on the automation PC."
            )
        raise


# ----------------------------------------------------------------------------
# Simple built-in scheduler: run every day at a fixed time
# ----------------------------------------------------------------------------
def parse_hhmm(value: str) -> tuple:
    try:
        hh, mm = value.split(":")
        hh, mm = int(hh), int(mm)
        if not (0 <= hh < 24 and 0 <= mm < 60):
            raise ValueError
        return hh, mm
    except ValueError:
        raise argparse.ArgumentTypeError("time must be in HH:MM format, e.g. 02:00")


def next_run_time(hh: int, mm: int) -> datetime:
    now = datetime.now()
    target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def run_scheduler(args) -> None:
    hh, mm = args.schedule
    logger.info(f"Scheduler mode: daily backup at {hh:02d}:{mm:02d} (Ctrl+C to stop)")
    try:
        while True:
            target = next_run_time(hh, mm)
            logger.info(f"Next backup: {target:%Y-%m-%d %H:%M}")
            while datetime.now() < target:
                time.sleep(min(30, max(1, (target - datetime.now()).total_seconds())))
            try:
                run_backup_cycle(args)
            except SystemExit:
                logger.error("Cycle aborted because of a configuration error; will retry at the next scheduled time.")
            except Exception:
                # Never let an unexpected error kill the long-running scheduler
                logger.exception("Unexpected error during backup cycle")
    except KeyboardInterrupt:
        logger.info("Scheduler stopped.")


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Config Backup Tool - NOC Automation")
    parser.add_argument("--devices", default=str(DEVICES_FILE), help="path to devices.json")
    parser.add_argument("--schedule", type=parse_hhmm, metavar="HH:MM",
                        help="run automatically every day at this time (e.g. 02:00)")
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS,
                        help="delete backups older than this many days (default: 15)")
    parser.add_argument("--workers", type=int, default=5, help="number of parallel connections")
    parser.add_argument("--push", action="store_true", help="git commit + push after the backup")
    parser.add_argument("--branch", default="main", help="git branch to push to")
    parser.add_argument("--no-encrypt", action="store_true",
                        help="(not recommended) store configs as plaintext instead of encrypting with age")
    parser.add_argument("--no-acl", action="store_true",
                        help="Windows only: do not modify folder ACLs with icacls")
    parser.add_argument("--no-alerts", action="store_true",
                        help="disable all alerts (Telegram + Zabbix)")
    parser.add_argument("--alert-only-failures", action="store_true",
                        help="send the Telegram message only when a backup fails "
                             "(Zabbix still receives every result)")
    args = parser.parse_args()

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    restrict_permissions(BACKUP_DIR, 0o700)
    if IS_WINDOWS and not args.no_acl:
        lock_down_windows_dir(BACKUP_DIR)

    if args.no_encrypt:
        logger.warning("Encryption is disabled: configs will be stored as PLAINTEXT! (never push them to GitHub)")
    else:
        if not AGE_RECIPIENT:
            if IS_WINDOWS:
                hint = 'PowerShell: setx AGE_RECIPIENT "age1..." (then open a new terminal)'
            else:
                hint = "export AGE_RECIPIENT='age1...'"
            logger.error(f"AGE_RECIPIENT is not set. Set it ({hint}) or use --no-encrypt.")
            sys.exit(1)
        if shutil.which("age") is None:
            hint = "winget install FiloSottile.age" if IS_WINDOWS else "sudo apt install age"
            logger.error(f"'age' was not found in PATH. Install it ({hint}) or use --no-encrypt.")
            sys.exit(1)

    if not args.no_alerts:
        channels = []
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            channels.append("Telegram")
        if ZABBIX_SERVER:
            channels.append("Zabbix")
        logger.info(f"Alerts enabled: {', '.join(channels) if channels else 'none configured'}")

    if args.schedule:
        run_scheduler(args)
    else:
        run_backup_cycle(args)


if __name__ == "__main__":
    main()