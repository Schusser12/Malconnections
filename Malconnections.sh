#!/bin/bash

# --- Setup ---
TMPDIR=$(mktemp -d)
SEEN="$TMPDIR/seen"
LOGFILE="$TMPDIR/outbound-$(date '+%F_%H%M%S').log"
ALERTS_FILE="$TMPDIR/alerts-summary.log"
START_TIME=$(date +%s)

# --- Terminal Colors ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# --- List of suspicious binaries and HTTP clients to monitor for ---
SUSPICIOUS_TOOLS="curl|wget|perl|python|python-requests|Go-http-client|Java|libwww-perl|httpclient|http-client|aiohttp|okhttp|axios|Scrapy|bash|sh"

# --- List of known safe processes to ignore for direct IP detection ---
SAFE_PROCESSES="nginx|filebeat|telegraf|imap-login|sshd|qmail-remote|puppet|sssd_be|aakore"

# --- Manual report mode ---
if [[ "$1" == "--report" ]]; then
    if [[ -s "$ALERTS_FILE" ]]; then
        echo -e "\n${RED}--- Potential Threats Found ---${NC}"
        cat "$ALERTS_FILE"
        echo -e "${RED}--- End of Alert Summary ---${NC}\n"
    else
        echo -e "\n${GREEN}No alerts recorded during this session.${NC}\n"
    fi
    exit 0
fi

# --- Handle CTRL+C to print summary ---
trap cleanup EXIT

cleanup() {
    echo -e "\n${YELLOW}Script interrupted. Showing alert summary...${NC}"
    echo -e "${YELLOW}Session ended at: $(date '+%F %T')${NC}"

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    HOURS=$((DURATION / 3600))
    MINUTES=$(( (DURATION % 3600) / 60 ))
    SECONDS=$((DURATION % 60))

    echo -e "${YELLOW}Session duration: ${HOURS}h ${MINUTES}m ${SECONDS}s${NC}"

    if [[ -s "$ALERTS_FILE" ]]; then
        echo -e "\n${RED}--- Potential Threats Found ---${NC}"
        cat "$ALERTS_FILE"
        echo -e "${RED}--- End of Alert Summary ---${NC}\n"
    else
        echo -e "\n${GREEN}No alerts recorded during this session.${NC}\n"
    fi
}

echo "Logging to: $LOGFILE"
touch "$SEEN"
touch "$ALERTS_FILE"

# --- Initial Maldet Report (runs once) ---
timestamp=$(date '+[%F %T]')
echo -e "\n$timestamp Recent Maldet scan results:" >> "$LOGFILE"
maldet=$(egrep "(scan completed on|scan report saved)" /usr/local/maldetect/logs/event_log 2>/dev/null | egrep "$(date +'%b %d %Y')|$(date -d 'yesterday' +'%b %d %Y')")
if [[ -z "$maldet" ]]; then
    echo -e "No Maldet scan activity found for today or yesterday.\n" >> "$LOGFILE"
else
    echo -e "$maldet\n" >> "$LOGFILE"
fi

# --- Monitor Loop ---
while true; do
    timestamp=$(date '+[%F %T]')
    echo -e "${GREEN}$timestamp Checking outbound connections...${NC}"
    echo "$timestamp Checking outbound connections..." >> "$LOGFILE"

    # --- Stealth Connection Check ---
    echo -e "\n$timestamp Stealth connection check:" >> "$LOGFILE"
    stealth=$(sudo netstat -npt 2>/dev/null | grep -i stealth)
    if [[ -z "$stealth" ]]; then
        echo "No stealth connections detected." >> "$LOGFILE"
    else
        echo "$stealth" >> "$LOGFILE"
        echo -e "${RED}[ALERT] Stealth connection detected!${NC}"
        echo "$timestamp [ALERT] Stealth connection detected!" >> "$ALERTS_FILE"
    fi

    # --- Suspicious PHP Socket Activity ---
    echo -e "\n$timestamp Suspicious PHP socket activity check:" >> "$LOGFILE"
    suspicious=""
    for ps in $(ps faux | egrep 'php' | awk '{print $2}' | grep -v PID); do
        output=$(sudo lsof -p "$ps" 2>/dev/null | egrep -i 'tcp|udp' | egrep "$(hostname)\.[0-9]")
        [[ -n "$output" ]] && suspicious+="$output"$'\n'
    done
    if [[ -z "$suspicious" ]]; then
        echo "No suspicious PHP socket activity detected." >> "$LOGFILE"
    else
        echo "$suspicious" >> "$LOGFILE"
        echo -e "${YELLOW}[Warning] Suspicious PHP socket activity detected!${NC}"
        echo "$timestamp [ALERT] Suspicious PHP socket activity detected!" >> "$ALERTS_FILE"
    fi

    # --- Outbound TCP Connection State Monitoring ---
    echo -e "\n$timestamp Outbound TCP connection states:" >> "$LOGFILE"
    close_wait_count=$(sudo ss -pnto state close-wait 2>/dev/null | grep -c ':80$\|:443$')
    sudo ss -pnto state established,close-wait,last-ack 2>/dev/null | awk '
        $5 ~ /:80$|:443$/ {
            print $1
        }
    ' | sort | uniq -c | sort -rnk1,1 >> "$LOGFILE"

    # --- Alert if too many CLOSE-WAITs ---
    if [[ $close_wait_count -gt 100 ]]; then
        echo -e "${RED}[ALERT] High number of CLOSE-WAIT connections detected! ($close_wait_count)${NC}"
        echo "$timestamp [ALERT] High number of CLOSE-WAIT connections detected! ($close_wait_count)" >> "$ALERTS_FILE"
    fi

    # --- PHP Outbound DNS Query Check ---
    echo -e "\n$timestamp PHP outbound DNS query check:" >> "$LOGFILE"
    php_dns=$(sudo ss -uap | grep '[p]hp' | grep ':53')
    if [[ -n "$php_dns" ]]; then
        echo "$timestamp [ALERT] PHP process making outbound DNS queries detected:" >> "$LOGFILE"
        echo "$php_dns" >> "$LOGFILE"
        echo -e "${RED}[ALERT] PHP outbound DNS detected!${NC}"
        echo "$timestamp [ALERT] PHP outbound DNS query detected!" >> "$ALERTS_FILE"
    else
        echo "No PHP DNS queries detected." >> "$LOGFILE"
    fi

    # --- Suspicious PHP Child Process Check ---
    echo -e "\n$timestamp Suspicious PHP child process check:" >> "$LOGFILE"
    for pid in $(ps faux | egrep '[p]hp' | awk '{print $2}'); do
        children=$(pgrep -P "$pid")
        for child in $children; do
            [[ ! -f "/proc/$child/cmdline" ]] && continue
            cmd=$(tr '\0' ' ' < /proc/$child/cmdline)

            # --- Detect use of suspicious PHP functions ---
            if [[ "$cmd" =~ (system|exec|shell_exec|popen) && ! "$cmd" =~ bin/magento && ! "$cmd" =~ wp-cron.php ]]; then
                echo "$timestamp [WARNING] PHP child process using suspicious function: $cmd" >> "$LOGFILE"
                echo -e "${RED}[ALERT] PHP suspicious function call: ${cmd}${NC}"
                echo "$timestamp [ALERT] PHP suspicious function call: $cmd" >> "$ALERTS_FILE"
            fi

            # --- Detect use of suspicious binaries ---
            if [[ "$cmd" =~ $SUSPICIOUS_TOOLS && ! "$cmd" =~ bin/magento && ! "$cmd" =~ wp-cron.php ]]; then
                echo "$timestamp Suspicious child process spawned by PHP PID $pid: $cmd" >> "$LOGFILE"
                echo -e "${YELLOW}[Warning] Suspicious PHP child process: ${cmd}${NC}"
                echo "$timestamp [ALERT] Suspicious PHP child process: $cmd" >> "$ALERTS_FILE"
            fi

            # --- Detect PHP scripts running from /tmp or /dev/shm ---
            php_files=$(sudo lsof -p "$child" 2>/dev/null | awk '$9 ~ /\.php$/ { print $9 }')
            if echo "$php_files" | grep -qE "/tmp/|/dev/shm/"; then
                echo "$timestamp [ALERT] PHP script running from temp folder: $php_files" >> "$LOGFILE"
                echo -e "${RED}[ALERT] PHP running from temp directory!${NC}"
                echo "$timestamp [ALERT] PHP running from temp directory: $php_files" >> "$ALERTS_FILE"
            fi
        done
    done

    # --- Outbound Connection Scanning for New PIDs ---
    echo -e "\n$timestamp Outbound connection scanning for new PIDs:" >> "$LOGFILE"
    while read -r pid; do
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue
        user=$(ps -o user= -p "$pid" 2>/dev/null)
        [[ "$user" == "aakore" || "$user" == "root" ]] && continue
        grep -qx "$pid" "$SEEN" && continue
        echo "$pid" >> "$SEEN"

        echo "$timestamp ----------------------------------------" >> "$LOGFILE"
        echo "PID: $pid" >> "$LOGFILE"
        echo "User: $user" >> "$LOGFILE"
        echo -n "Cmdline: " >> "$LOGFILE"
        tr '\0' ' ' < /proc/$pid/cmdline >> "$LOGFILE"
        echo -e "\nCWD: $(readlink /proc/$pid/cwd 2>/dev/null)" >> "$LOGFILE"
        echo -e "EXE: $(readlink /proc/$pid/exe 2>/dev/null)" >> "$LOGFILE"
        
        php_files=$(sudo lsof -p "$pid" 2>/dev/null | awk '$9 ~ /\.php$/ { print $9 }')
        if [[ -n "$php_files" ]]; then
            echo "Open .php files:" >> "$LOGFILE"
            echo "$php_files" >> "$LOGFILE"
        fi
        echo >> "$LOGFILE"
    done < <(
        sudo ss -ntp 2>/dev/null |
        awk '$1 == "ESTAB" && $5 ~ /:80$|:443$/ && $6 ~ /pid=/ {
            match($6, /pid=([0-9]+)/, a)
            if (a[1]) print a[1]
        }' | sort -u
    )

# --- Direct IP Connection Detection ---
echo -e "\n$timestamp Direct IP connection detection:" >> "$LOGFILE"
while read -r line; do
    remote=$(echo "$line" | awk '{print $5}')
    pidinfo=$(echo "$line" | awk '{print $6}')

    # Extract IP (before :port)
    ip="${remote%:*}"

    # Skip local/private IPs
    if [[ "$ip" =~ ^127\. ]] || [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        continue
    fi

    # Only alert if remote is a raw IP
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Extract PID cleanly
        if [[ "$pidinfo" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"

            # Find process name
            pname=$(ps -p "$pid" -o comm= 2>/dev/null)
            pname=${pname:-unknown}

            # Skip if it's a known safe process
            if [[ "$pname" =~ $SAFE_PROCESSES ]]; then
                continue
            fi

            # Look for open PHP files for that PID
            php_files=$(sudo lsof -p "$pid" 2>/dev/null | awk '$9 ~ /\.php$/ { print $9 }')

            if [[ -n "$php_files" ]]; then
                echo "[ALERT] Direct IP connection detected: $ip by PID $pid (PHP files: $php_files)" | tee -a "$LOGFILE"
                echo "$timestamp [ALERT] Direct IP connection detected: $ip by PID $pid (PHP files: $php_files)" >> "$ALERTS_FILE"
            else
                echo "[ALERT] Direct IP connection detected: $ip (Process: $pname PID $pid)" | tee -a "$LOGFILE"
                echo "$timestamp [ALERT] Direct IP connection detected: $ip (Process: $pname PID $pid)" >> "$ALERTS_FILE"
            fi
        else
            echo "[ALERT] Direct IP connection detected: $ip (Info: $pidinfo)" | tee -a "$LOGFILE"
            echo "$timestamp [ALERT] Direct IP connection detected: $ip (Info: $pidinfo)" >> "$ALERTS_FILE"
        fi
    fi
done < <(
    sudo ss -ntp 2>/dev/null | grep ESTAB
)

    # --- Pause before next check ---
    sleep 2
done
