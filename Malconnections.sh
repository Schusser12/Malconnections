#!/bin/bash

TMPDIR=$(mktemp -d)
SEEN="$TMPDIR/seen"
LOGFILE="$TMPDIR/outbound-$(date '+%F_%H%M%S').log"

echo "Logging to: $LOGFILE"

touch "$SEEN"

# --- Maldet scan report summary (runs once) ---
timestamp=$(date '+[%F %T]')
echo -e "\n$timestamp Recent Maldet scan results:" >> "$LOGFILE"
maldet=$(egrep "(scan completed on|scan report saved)" /usr/local/maldetect/logs/event_log 2>/dev/null | egrep "$(date +'%b %d %Y')|$(date -d 'yesterday' +'%b %d %Y')")
if [[ -z "$maldet" ]]; then
    echo -e "No Maldet scan activity found for today or yesterday.\n" >> "$LOGFILE"
else
    echo -e "$maldet \n" >> "$LOGFILE"
fi

while true; do
    timestamp=$(date '+[%F %T]')
    echo "$timestamp Checking outbound connections..." >> "$LOGFILE"

    # --- Stealth connection check ---
    echo -e "\n$timestamp Stealth connection check:" >> "$LOGFILE"
    stealth=$(sudo netstat -npt 2>/dev/null | grep -i stealth)
    if [[ -z "$stealth" ]]; then
        echo "No stealth connections detected." >> "$LOGFILE"
    else
        echo "$stealth" >> "$LOGFILE"
    fi

    # --- Suspicious PHP socket connections ---
    echo -e "\n$timestamp Suspicious PHP socket activity check:" >> "$LOGFILE"
    suspicious=""
    for ps in $(ps faux | egrep 'php' | awk '{print $2}' | grep -v PID); do
        output=$(sudo lsof -p "$ps" 2>/dev/null | egrep -i 'tcp|udp' | egrep "$(hostname)\.[0-9]")
        [[ -n "$output" ]] && suspicious+="$output"$'\n'
    done
    if [[ -z "$suspicious" ]]; then
        echo -e "No suspicious PHP socket activity detected.\n" >> "$LOGFILE"
    else
        echo "$suspicious" >> "$LOGFILE"
    fi

    # --- Outbound connection scanning ---
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

    sleep 2
done
