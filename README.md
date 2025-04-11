# 🕵️ Outbound Connection & PHP Activity Monitor

A simple bash-based monitoring script to log outbound network activity from processes, with a focus on PHP-based behaviors. Useful for detecting potential web shell activity, suspicious connections, or early signs of compromise on a Linux server.

---

## 🔧 What It Does

- Monitors **established outbound connections** on ports `80` and `443`
- Logs the following for **new processes**:
  - PID, user, command line, working directory
  - Any `.php` files opened by the process
- Skips trusted users like `root` and `aakore`
- Checks for:
  - **Stealth connections** (`netstat | grep stealth`)
  - **PHP socket connections** to suspicious ports
  - **Recent Maldet scan activity** (only once at startup)
- Logs everything to a unique file inside a temporary directory

---

## 🧪 Sample Log Snippet

```log
[2025-04-11 20:22:15] Checking outbound connections...

[2025-04-11 20:22:15] Stealth connection check:
No stealth connections detected.

[2025-04-11 20:22:15] Suspicious PHP socket activity check:
No suspicious PHP socket activity detected.

[2025-04-11 20:22:15] ----------------------------------------
PID: 9412
User: testme
Cmdline: /usr/bin/php -f /var/www/html/index.php
CWD: /var/www/html
Open .php files:
/var/www/html/index.php
