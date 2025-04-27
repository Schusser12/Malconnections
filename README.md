# 🕵️ Outbound Connection & PHP Activity Monitor

A lightweight Bash-based monitoring script that watches for suspicious outbound activity on Linux servers — with a special focus on PHP-related behaviors often linked to web shells, malware, or unauthorized tools.

---

## 🔧 What It Does

- Monitors **outbound TCP connections** (ports 80 and 443)
- Logs the following for **new processes**:
  - PID, user, command line, current working directory (CWD), and executable path
  - Any `.php` files opened by the process
- Skips trusted users (e.g., `root`, `aakore`)
- Skips trusted processes (e.g., `nginx`, `filebeat`, etc.)
- Detects and alerts on:
  - Direct IP connections (bypassing DNS)
  - Suspicious PHP socket activity
  - PHP scripts executing from `/tmp` or `/dev/shm`
  - Use of dangerous PHP functions (`system`, `exec`, `popen`, etc.)
  - PHP processes calling tools like `curl`, `wget`, `python`, etc.
  - PHP outbound DNS activity
  - Excessive CLOSE-WAIT socket states
- Performs a **one-time Maldet scan log check** at startup
- Gracefully handles `CTRL+C` to show an alert summary

---

## 📁 Files Created (Per Session)

All stored inside a temporary directory (`/tmp/...`):

| File                     | Description                                      |
|---------------------------|--------------------------------------------------|
| `alerts-summary.log`      | All triggered alerts from this session           |
| `scan-summary.log`        | Full session summary (duration, stats, etc.)      |
| `outbound-YYYY-MM-DD.log` | Timestamped connection and scan activity logs    |
| `seen`                    | Tracks already analyzed PIDs to avoid duplicates |
| `pid_snapshots/`          | Full snapshots of suspicious processes detected  |

---

## 🧪 Sample Log Snippet

```log
[2025-04-11 20:22:15] [INFO] Checking outbound connections...

[2025-04-11 20:22:15] [INFO] No stealth connections detected.

[2025-04-11 20:22:15] [INFO] No suspicious PHP socket activity detected.

----------------------------------------
PID: 9412
User: testme
Cmdline: /usr/bin/php -f /var/www/html/index.php
CWD: /var/www/html
Open .php files:
- /var/www/html/index.php
```

---

## 🚀 Usage
Clone the repository and start the monitor:
```bash
bash Malconnections.sh
```
---

### Optional Flags

| Flag        | Description                                       |
|-------------|---------------------------------------------------|
| `--help`    | Show usage instructions                           |
| `--report`  | Display the previous session’s alerts and summary |

---
