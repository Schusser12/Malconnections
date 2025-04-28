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
- Auto GeoIP lookup of suspicious IP addresses (via `ipwho.is`)
- Parallel background GeoIP downloads (safe, rate-limited)
- Compressed timestamped error logging (`live-session.log.gz`)
- Graceful shutdown with session summaries and cleanup on CTRL+C

---

## 📁 Files Created (Per Session)

All session artifacts are saved inside `/tmp/tmp.<random>/`:

| File                      | Description                                         |
|---------------------------|-----------------------------------------------------|
| `alerts-summary.log`      | All triggered alerts from this session              |
| `scan-summary.log`        | Full session summary (duration, stats, etc.)        |
| `outbound-YYYY-MM-DD.log` | Timestamped connection and scan activity logs       |
| `seen`                    | Tracks already analyzed PIDs to avoid duplicates    |
| `pid_snapshots/`          | Full snapshots of suspicious processes detected     |
| `live-session.log.gz`     | **Compressed timestamped error logs** (stderr only) |
| `geoip_lookup_<IP>.json`  | GeoIP data per suspicious direct IP connection      |

---

## 🧪 Sample Log Snippet

```log
[2025-04-11 20:22:15] [INFO] Checking outbound connections...
[2025-04-11 20:22:15] [INFO] No stealth connections detected.
[2025-04-11 20:22:15] [INFO] No suspicious PHP socket activity detected.
[2025-04-11 20:22:15] TCP Connection Summary:
  4 ESTAB
  1 CLOSE-WAIT

[2025-04-11 20:22:16] [ALERT] Direct IP connection detected! IP: 45.12.34.56 [RU] Process: php-fpm
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
