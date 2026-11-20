import os
import subprocess
import logging
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)


def send_telegram(text: str) -> bool:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        log.warning("Telegram env vars not set, skipping alert")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as r:
            return r.status == 200
    except Exception as e:
        # متطبعش الـ url أو الـ exception كامل عشان الـ token ميتسربش في اللوج
        log.error("Telegram send failed: %s", type(e).__name__)
        return False


def send_zabbix(host: str, key: str, value) -> bool:
    server = os.environ.get("ZABBIX_SERVER", "192.168.100.5")
    cmd = ["zabbix_sender", "-z", server, "-p", "10051",
           "-s", host, "-k", key, "-o", str(value)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.error("zabbix_sender failed: %s", type(e).__name__)
        return False
    ok = r.returncode == 0 and "failed: 0" in r.stdout
    if not ok:
        log.error("zabbix_sender output: %s", r.stdout.strip() or r.stderr.strip())
    return ok