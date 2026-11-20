# Config Backup Tool

Automated, encrypted configuration backups for network devices, with **Telegram** and **Zabbix** alerting. Built for a NOC workflow and tested in an EVE-NG lab with Cisco IOSv devices.

The tool connects to every device in `devices.json` over SSH (Netmiko), pulls the running configuration, encrypts it with [age](https://github.com/FiloSottile/age) before it touches the disk, keeps a rolling 15-day history, and reports the result of every run to Telegram (for humans) and Zabbix (for monitoring).

---

## Features

- **Parallel backups** of many devices (Netmiko + thread pool)
- **One folder per device**: `backups/<device>/<device>_<timestamp>.cfg.age`
- **Encryption at rest** with age public-key encryption. Plaintext is piped to `age` through stdin and is never written to disk
- **Retention policy**: deletes backups older than N days (default 15) but always keeps the newest backup of every device
- **Built-in daily scheduler** (`--schedule HH:MM`) or use cron / Windows Task Scheduler
- **Telegram alerts**: one summary per run, listing the failed devices and the reason
- **Zabbix alerts**: per-device status and message sent with `zabbix_sender`, so you get a trigger on failure *and* on "the script did not run at all"
- **Secrets never in code**: passwords, age key, Telegram token are read from environment variables
- **Optional git commit/push** of the encrypted backups
- Works on **Linux and Windows**

---

## Lab topology

| Device | Role | Address |
|---|---|---|
| R1 | Edge router | 192.168.10.1 |
| MSW | Multilayer switch (inter-VLAN routing) | 192.168.100.3 / 192.168.10.2 / 192.168.200.1 |
| Automation PC | Runs this tool | VLAN10 (Management, 192.168.100.0/24) |
| Zabbix server | Receives results on port 10051 | 192.168.100.5 |
| Linux host | Management VLAN host | VLAN10 |
| Parrot | Red Team host | VLAN20 (192.168.200.0/24) |

Recommended: add an ACL on MSW so VLAN20 (Red Team) cannot reach VLAN10 (Management), especially the Zabbix port `10051`.

```
 Automation PC (VLAN10)
   │  SSH (Netmiko)
   ├──────────────► R1, MSW ...   pull running-config
   │
   ├─ age ────────► backups/<device>/*.cfg.age
   │
   ├─ HTTPS ──────► api.telegram.org      (summary message)
   └─ zabbix_sender ► Zabbix server :10051 (per-device status + message)
```

---

## Requirements

- Python 3.8+
- `pip install netmiko`
- [`age`](https://github.com/FiloSottile/age) in `PATH`
  - Windows: `winget install FiloSottile.age`
  - Debian/Ubuntu: `sudo apt install age`
- `zabbix_sender` (only for Zabbix alerts), part of the Zabbix agent package
- A Telegram bot (only for Telegram alerts)

---

## Installation

```bash
git clone <your-repo-url>
cd noc-security/src/Config_Backup_Tool
pip install netmiko
```

### 1. Create the age key pair

```bash
age-keygen -o key.txt
```

- The line printed as `Public key: age1...` is your **recipient**. It is safe to put in an environment variable.
- Keep `key.txt` (the private key) **offline**. It is only needed to restore/decrypt a config.

### 2. Create `devices.json`

```json
[
  {
    "name": "MSW",
    "host": "192.168.100.3",
    "username": "admin",
    "password_env": "MSW_PASSWORD",
    "device_type": "cisco_ios",
    "secret_env": "MSW_ENABLE"
  },
  {
    "name": "R1",
    "host": "192.168.10.1",
    "username": "admin",
    "password_env": "R1_PASSWORD",
    "device_type": "cisco_ios"
  }
]
```

| Field | Required | Description |
|---|---|---|
| `name` | no | Folder/file name. If omitted, it is taken from the device prompt |
| `zabbix_host` | no | Host name in Zabbix, if different from `name` |
| `host` | yes | IP or DNS name |
| `username` | yes | SSH user |
| `password` / `password_env` | one of | Password, or the name of an environment variable holding it (preferred) |
| `key_file` | alt. | SSH private key instead of a password |
| `device_type` | no | Netmiko type, default `cisco_ios` |
| `secret` / `secret_env` | no | Enable password |

Supported out of the box: `cisco_ios`, `cisco_xe`, `cisco_nxos`, `cisco_asa`, `juniper_junos`, `arista_eos`, `huawei`, `fortinet`. Add more in `SHOW_RUN_COMMANDS`.

### 3. Set environment variables

Windows (PowerShell, then **open a new terminal / restart the parent app**):

```powershell
setx AGE_RECIPIENT "age1...."
setx MSW_PASSWORD "..."
setx R1_PASSWORD  "..."
```

Linux:

```bash
export AGE_RECIPIENT='age1....'
```

> `setx` only affects **new** processes. If a variable looks empty, close the terminal application completely and reopen it.

---

## Usage

```bash
python Config_Backup_Tool.py                         # run once, now
python Config_Backup_Tool.py --schedule 02:00        # stay alive, back up daily at 02:00
python Config_Backup_Tool.py --retention-days 30     # change retention (default 15)
python Config_Backup_Tool.py --workers 10            # parallel connections (default 5)
python Config_Backup_Tool.py --push                  # also git commit + push
python Config_Backup_Tool.py --alert-only-failures   # Telegram only on failure
python Config_Backup_Tool.py --no-alerts             # disable Telegram + Zabbix
python Config_Backup_Tool.py --devices other.json    # use another devices file
```

| Flag | Description |
|---|---|
| `--devices PATH` | Path to the devices file (default `devices.json`) |
| `--schedule HH:MM` | Run every day at this time and keep running |
| `--retention-days N` | Delete backups older than N days (default 15) |
| `--workers N` | Number of parallel connections (default 5) |
| `--push` / `--branch` | Git commit and push after the run |
| `--no-encrypt` | Store plaintext (lab only, never push such files) |
| `--no-acl` | Windows: do not modify folder ACLs with `icacls` |
| `--no-alerts` | Disable all alerts |
| `--alert-only-failures` | Telegram message only when something fails (Zabbix always receives every result) |

### Scheduling (recommended)

**Windows Task Scheduler**, run as the same user that owns the environment variables:

```powershell
schtasks /Create /TN "ConfigBackup" /SC DAILY /ST 02:00 /F /TR "\"C:\Path\To\python.exe\" \"D:\Path\To\Config_Backup_Tool.py\""
schtasks /Run /TN "ConfigBackup"      # test it immediately, then check backup.log
```

**Linux**: a cron entry or a systemd timer that runs the script without `--schedule`.

---

## Alerts

All alert settings are environment variables. A channel that is not configured is simply skipped, and an alert failure never breaks the backup itself. The startup log shows what is active, for example `Alerts enabled: Telegram, Zabbix`.

### Telegram

1. Talk to **@BotFather**, send `/newbot`, and copy the token.
2. Send any message to your new bot.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id` from the response.
4. Store them:

```powershell
setx TELEGRAM_BOT_TOKEN "123456:ABC..."
setx TELEGRAM_CHAT_ID   "123456789"
```

Example messages:

```
✅ Config backup OK: 2/2 devices (2026-11-20 18:41)
Retention: removed 0 file(s) older than 15 days
```

```
❌ Config backup: 1/2 FAILED (2026-11-20 18:41)
- R1 (192.168.10.1): No response from 192.168.10.1 (timeout)
OK: MSW
Retention: removed 0 file(s) older than 15 days
```

> The token is never logged. If it is ever exposed, revoke it with `/revoke` in @BotFather and generate a new one.

### Zabbix

The tool pushes results with `zabbix_sender` into **trapper** items. One `zabbix_sender` call per run sends two values per device:

| Key | Type | Meaning |
|---|---|---|
| `config.backup.status` | Numeric (unsigned) | `0` = OK, `1` = FAILED |
| `config.backup.message` | Text | Saved file name, or the error |

Environment variables:

```powershell
setx ZABBIX_SERVER "192.168.100.5"
setx ZABBIX_SENDER "C:\Path\To\zabbix_sender.exe"   # only if not in PATH
# optional: ZABBIX_PORT (default 10051)
```

Get `zabbix_sender.exe` on Windows:

```powershell
$ProgressPreference = 'SilentlyContinue'
$url  = "https://cdn.zabbix.com/zabbix/binaries/stable/7.0/latest/zabbix_agent-7.0-latest-windows-amd64-openssl.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\zabbix_agent.zip"
Expand-Archive -Path "$env:TEMP\zabbix_agent.zip" -DestinationPath "$env:USERPROFILE\Tools\zabbix" -Force
```

**Zabbix frontend setup**, for every device:

1. **Host**: the host name must match the device `name` exactly (case-sensitive), or set `zabbix_host` in `devices.json`.
2. **Item 1**: Type *Zabbix trapper*, key `config.backup.status`, Numeric (unsigned), *Allowed hosts* = IP of the machine running the tool.
3. **Item 2**: Type *Zabbix trapper*, key `config.backup.message`, Text, same *Allowed hosts*.
4. **Triggers** (Zabbix 6.x / 7.x syntax):

| Name | Expression | Severity |
|---|---|---|
| Config backup FAILED on {HOST.NAME} | `last(/HOST/config.backup.status)=1` | High |
| No config backup result from {HOST.NAME} for 26h | `nodata(/HOST/config.backup.status,26h)=1` | Average |

The second trigger is the important one: if the PC is off or the scheduled task stopped, no failure is ever reported, but Zabbix notices that the data stopped arriving.

**Manual test** before running the tool:

```powershell
& $env:ZABBIX_SENDER -z 192.168.100.5 -s MSW -k config.backup.status -o 1   # trigger should open
& $env:ZABBIX_SENDER -z 192.168.100.5 -s MSW -k config.backup.status -o 0   # trigger should close
```

`processed: 1; failed: 0` means the host, key and *Allowed hosts* are correct.

---

## Restoring a config

```bash
age -d -i key.txt backups/MSW/MSW_20261120_184112.cfg.age > MSW.cfg
```

---

## Retention logic

- Files are matched by `<name>_YYYYMMDD_HHMMSS.cfg[.age]`; the timestamp in the file name is used, not the modified time.
- Anything older than `--retention-days` is deleted.
- The **newest backup of each device is always kept**, so a device that stopped responding never loses its last known good config.

---

## Security notes

- Never commit `devices.json` with plaintext passwords, `key.txt`, or `backup.log`. Prefer `password_env`.
- Recommended `.gitignore`:

```gitignore
devices.json
backups/
backup.log
key.txt
*.cfg
```

- On Linux the backup folders are `chmod 700` and the files `600`. On Windows the backup root is restricted to the current user with `icacls` (use `--no-acl` if the task runs under a different account).
- Never use `--no-encrypt` for anything pushed to GitHub.
- Restrict *Allowed hosts* on the Zabbix items and block untrusted VLANs from reaching the Zabbix port.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Alerts enabled: none configured` | Environment variables are not visible to this process. Close the terminal app completely and reopen it, or check with `[Environment]::GetEnvironmentVariable("ZABBIX_SERVER","User")` |
| `& $env:ZABBIX_SENDER ... not valid` | `ZABBIX_SENDER` is empty in this session |
| `Telegram alert failed: HTTP 401/404` | Wrong or revoked bot token |
| `getUpdates` returns `"result":[]` | Send a message to the bot first, then reload |
| `Zabbix: ... failed: N` | Host name or item key mismatch, item is not type *trapper*, or the sender IP is not in *Allowed hosts* |
| `zabbix_sender was not found` | Set `ZABBIX_SENDER` to the full path |
| `Authentication failed` | Wrong credentials, or the `*_env` variable is empty |
| `AGE_RECIPIENT is not set` | Set it, or use `--no-encrypt` (lab only) |
| `CryptographyDeprecationWarning` (TripleDES) | Harmless warning from paramiko |
| Zabbix item `No Such Object available on this agent at this OID` | Unrelated to backups: the IOSv image does not support that SNMP OID. Disable that item |

---

## Project layout

```
Config_Backup_Tool/
├── Config_Backup_Tool.py
├── devices.json          # not committed
├── backups/              # not committed
│   ├── MSW/MSW_<timestamp>.cfg.age
│   └── R1/R1_<timestamp>.cfg.age
└── backup.log            # rotating log, not committed
```

## Roadmap

- Scheduled run through Task Scheduler / systemd with a health check
- ACL on the core switch to isolate the Red Team VLAN from management
- Config diff between consecutive backups (change detection)
- Zabbix-to-Telegram notifications from the Zabbix side