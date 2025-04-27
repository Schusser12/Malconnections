#!/bin/bash

# --- Setup ---
timestamp() { date '+[%F %T]'; }

TMPDIR=$(mktemp -d)
SEEN="$TMPDIR/seen"
LOGFILE="$TMPDIR/outbound-$(date '+%F_%H%M%S').log"
ALERTS_FILE="$TMPDIR/alerts-summary.log"
SUMMARY_FILE="$TMPDIR/scan-summary.log"
START_TIME=$(date +%s)

SNAPSHOT_DIR="$TMPDIR/pid_snapshots"
mkdir -p "$SNAPSHOT_DIR"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

trap cleanup EXIT

# --- Alert counters ---
TOTAL_ALERTS=0
STEALTH_ALERTS=0
PHP_SUSPICIOUS=0
DIRECT_IP_ALERTS=0
STANDALONE_PHP_FILES=0

# --- Suspicious tools ---
SUSPICIOUS_TOOLS="curl|wget|perl|python|python-requests|Go-http-client|Java|libwww-perl|httpclient|http-client|aiohttp|okhttp|axios|Scrapy|bash|sh"

# --- Safe processes ---
SAFE_PROCESSES="nginx|filebeat|telegraf|imap-login|sshd|qmail-remote|puppet|sssd_be|aakore|newrelic-daemon|service_process"

cleanup() {
    echo -e "\n${YELLOW}$(timestamp) Script interrupted. Showing alert summary...${NC}"
    echo -e "${YELLOW}$(timestamp) Session ended at: $(date '+%F %T')${NC}"

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    HOURS=$((DURATION / 3600))
    MINUTES=$(( (DURATION % 3600) / 60 ))
    SECONDS=$((DURATION % 60))

    echo -e "\n${YELLOW}================ Session Summary ================${NC}"
    echo -e "${YELLOW}Session Duration:   ${HOURS}h ${MINUTES}m ${SECONDS}s${NC}"
    echo -e "${YELLOW}Total Alerts:       ${TOTAL_ALERTS}${NC}"
    echo -e "${YELLOW}Stealth Detections: ${STEALTH_ALERTS}${NC}"
    echo -e "${YELLOW}PHP Suspicious:     ${PHP_SUSPICIOUS}${NC}"
    echo -e "${YELLOW}Direct IP Hits:     ${DIRECT_IP_ALERTS}${NC}"
    echo -e "${YELLOW}Standalone PHP Files: ${STANDALONE_PHP_FILES}${NC}"
    echo -e "${YELLOW}===============================================${NC}"

    {
        echo "================ Session Summary ================"
        echo "Session Date:       $(date '+%F %T')"
        echo "Session Duration:   ${HOURS}h ${MINUTES}m ${SECONDS}s"
        echo "Total Alerts:       ${TOTAL_ALERTS}"
        echo "Stealth Detections: ${STEALTH_ALERTS}"
        echo "PHP Suspicious:     ${PHP_SUSPICIOUS}"
        echo "Direct IP Hits:     ${DIRECT_IP_ALERTS}"
        echo "Standalone PHP Files: ${STANDALONE_PHP_FILES}"
        echo "Temporary Files:    $TMPDIR"
        echo "=================================================="
    } >> "$SUMMARY_FILE"

    echo -e "\n${GREEN}$(timestamp) Temporary files saved in: $TMPDIR${NC}"
}

# --- Manual report mode ---
if [[ "$1" == "--report" ]]; then
    if [[ -s "$ALERTS_FILE" ]]; then
        echo -e "\n${RED}$(timestamp) --- Potential Threats Found ---${NC}"
        cat "$ALERTS_FILE"
        echo -e "${RED}$(timestamp) --- End of Alert Summary ---${NC}\n"
    else
        echo -e "\n${GREEN}$(timestamp) No alerts recorded during this session.${NC}\n"
    fi
    exit 0
fi

echo "Logging to: $LOGFILE"
touch "$SEEN"
touch "$ALERTS_FILE"

# --- Initial Maldet Report ---
echo -e "\n$(timestamp) Recent Maldet scan results:" >> "$LOGFILE"
maldet=$(grep -E "(scan completed on|scan report saved)" /usr/local/maldetect/logs/event_log 2>/dev/null | grep -E "$(date +'%b %d %Y')|$(date -d 'yesterday' +'%b %d %Y')")
if [[ -z "$maldet" ]]; then
    echo "$(timestamp) [INFO] No Maldet scan activity found for today or yesterday." >> "$LOGFILE"
else
    echo "$maldet" >> "$LOGFILE"
fi

# --- Monitor Loop ---
while true; do
    echo -e "${GREEN}$(timestamp) [INFO] Checking outbound connections...${NC}"
    echo "$(timestamp) [INFO] Checking outbound connections..." >> "$LOGFILE"

    # --- Stealth connection check ---
    stealth=$(sudo netstat -npt 2>/dev/null | grep -i stealth)
    if [[ -n "$stealth" ]]; then
        echo "$stealth" >> "$LOGFILE"
        echo -e "${RED}$(timestamp) [ALERT] Stealth connection detected!${NC}"
        echo "$(timestamp) [ALERT] Stealth connection detected!" >> "$ALERTS_FILE"
        ((TOTAL_ALERTS++))
        ((STEALTH_ALERTS++))
    else
        echo "$(timestamp) [INFO] No stealth connections detected." >> "$LOGFILE"
    fi

    # --- Suspicious PHP Socket Activity ---
    suspicious=""
    for ps in $(ps faux | grep -E '[p]hp' | awk '{print $2}'); do
        output=$(sudo lsof -p "$ps" 2>/dev/null | grep -Ei 'tcp|udp' | grep -E "$(hostname)\.[0-9]")
        [[ -n "$output" ]] && suspicious+="$output"$'\n'
    done
    if [[ -n "$suspicious" ]]; then
        echo "$suspicious" >> "$LOGFILE"
        echo -e "${YELLOW}$(timestamp) [WARN] Suspicious PHP socket activity detected!${NC}"
        echo "$(timestamp) [WARN] Suspicious PHP socket activity detected!" >> "$ALERTS_FILE"
        ((TOTAL_ALERTS++))
        ((PHP_SUSPICIOUS++))
    else
        echo "$(timestamp) [INFO] No suspicious PHP socket activity detected." >> "$LOGFILE"
    fi

    # --- Outbound TCP Connection States ---
    close_wait_count=$(sudo ss -pnto | awk '($1=="CLOSE-WAIT"){for(i=1;i<=NF;i++){if($i~/:80$|:443$/){print}}}' | wc -l)
    sudo ss -pnto | awk '
        ($1 == "ESTAB" || $1 == "CLOSE-WAIT" || $1 == "LAST-ACK") {
            for (i=1; i<=NF; i++) {
                if ($i ~ /:80$|:443$/) {
                    print $1
                    break
                }
            }
    }' | sort | uniq -c | sort -rnk1,1 >> "$LOGFILE"

    if [[ $close_wait_count -gt 100 ]]; then
        echo -e "${RED}$(timestamp) [ALERT] High number of CLOSE-WAIT connections detected! ($close_wait_count)${NC}"
        echo "$(timestamp) [ALERT] High number of CLOSE-WAIT connections detected! ($close_wait_count)" >> "$ALERTS_FILE"
        ((TOTAL_ALERTS++))
    fi

    # --- PHP Outbound DNS Query Check ---
    php_dns=$(sudo ss -uap | grep '[p]hp' | grep ':53')
    if [[ -n "$php_dns" ]]; then
        echo "$php_dns" >> "$LOGFILE"
        echo -e "${RED}$(timestamp) [ALERT] PHP process making outbound DNS queries detected!${NC}"
        echo "$(timestamp) [ALERT] PHP outbound DNS query detected!" >> "$ALERTS_FILE"
        ((TOTAL_ALERTS++))
        ((PHP_SUSPICIOUS++))
    else
        echo "$(timestamp) [INFO] No PHP DNS queries detected." >> "$LOGFILE"
    fi

    # --- Suspicious PHP Child Process Check ---
    for pid in $(ps faux | grep -E '[p]hp' | awk '{print $2}'); do
        children=$(pgrep -P "$pid")
        for child in $children; do
            [[ ! -f "/proc/$child/cmdline" ]] && continue
            cmd=$(tr '\0' ' ' < "/proc/$child/cmdline")

            if [[ "$cmd" =~ (system|exec|shell_exec|popen) && ! "$cmd" =~ bin/magento && ! "$cmd" =~ wp-cron.php ]]; then
                echo -e "${RED}$(timestamp) [ALERT] PHP suspicious function call: $cmd${NC}"
                echo "$(timestamp) [ALERT] PHP suspicious function call: $cmd" >> "$ALERTS_FILE"
                ((TOTAL_ALERTS++))
                ((PHP_SUSPICIOUS++))
            fi

            if [[ "$cmd" =~ $SUSPICIOUS_TOOLS && ! "$cmd" =~ bin/magento && ! "$cmd" =~ wp-cron.php ]]; then
                echo -e "${YELLOW}$(timestamp) [WARN] Suspicious PHP child process: $cmd${NC}"
                echo "$(timestamp) [WARN] Suspicious PHP child process: $cmd" >> "$ALERTS_FILE"
                ((TOTAL_ALERTS++))
                ((PHP_SUSPICIOUS++))
            fi

            php_files=$(sudo lsof -p "$child" 2>/dev/null | awk '$9 ~ /\.php$/ { print $9 }')
            if echo "$php_files" | grep -qE "/tmp/|/dev/shm/"; then
                echo -e "${RED}$(timestamp) [ALERT] PHP running from temp directory!${NC}"
                echo "$(timestamp) [ALERT] PHP script running from temp folder: $php_files" >> "$ALERTS_FILE"
                ((TOTAL_ALERTS++))
                ((PHP_SUSPICIOUS++))
            fi
        done
    done

    # --- Check for orphan PHP files ---
    orphan_php_files=$(find /tmp /dev/shm -type f -name "*.php" 2>/dev/null)
    if [[ -n "$orphan_php_files" ]]; then
        echo "$orphan_php_files" >> "$LOGFILE"
        echo -e "${RED}$(timestamp) [ALERT] Standalone PHP files found!${NC}"
        echo "$(timestamp) [ALERT] Standalone PHP files detected:" >> "$ALERTS_FILE"
        echo "$orphan_php_files" >> "$ALERTS_FILE"
        ((TOTAL_ALERTS++))
        ((STANDALONE_PHP_FILES++))
    fi

    # --- Outbound PID Monitoring ---
    while read -r pid; do
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue
        grep -qx "$pid" "$SEEN" && continue
        echo "$pid" >> "$SEEN"

        echo "$(timestamp) Outbound PID detected: $pid" >> "$LOGFILE"
    done < <(
        sudo ss -ntp 2>/dev/null |
        awk '$1 == "ESTAB" && $5 ~ /:80$|:443$/ && $6 ~ /pid=/ {match($6, /pid=([0-9]+)/, a); if (a[1]) print a[1]}' | sort -u
    )

    # --- Direct IP Connection Detection ---
    while read -r line; do
        remote=$(echo "$line" | awk '{print $5}')
        pidinfo=$(echo "$line" | awk '{print $6}')
        ip="${remote%:*}"

        if [[ "$ip" =~ ^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            continue
        fi

        if [[ "$pidinfo" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"
            pname=$(ps -p "$pid" -o comm= 2>/dev/null)
            [[ "$pname" =~ $SAFE_PROCESSES ]] && continue

            snapshot_file="$SNAPSHOT_DIR/snapshot_pid_${pid}_$(date '+%H%M%S_%N').log"
            {
                echo "--- Snapshot for PID $pid ---"
                tr '\0' ' ' < "/proc/$pid/cmdline"
                readlink "/proc/$pid/cwd"
                readlink "/proc/$pid/exe"
                sudo lsof -p "$pid" 2>/dev/null
                echo "--- End Snapshot ---"
            } >> "$snapshot_file"

            echo -e "${RED}$(timestamp) [ALERT] Direct IP connection detected! IP: $ip Process: $pname${NC}"
            echo "$(timestamp) [ALERT] Direct IP connection: $ip by $pname PID $pid" >> "$ALERTS_FILE"
            ((TOTAL_ALERTS++))
            ((DIRECT_IP_ALERTS++))
        fi
    done < <(sudo ss -ntp 2>/dev/null | grep ESTAB)

    sleep 2
done
