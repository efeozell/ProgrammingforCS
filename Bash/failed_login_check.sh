#!/bin/bash

LOGFILE="/var/log/auth.log"
PATTERN="Failed password for"
RECIPIENT="email@address.com"
SUBJECT="Invalid Login Attempts Detected"

message=""

if [ -f "$LOGFILE" ]; then
    while IFS= read -r line; do
        if [[ "$line" =~ $PATTERN ]]; then
            # It extracts the username following the word 'for' and the IP address following the word 'from'
            user=$(echo "$line" | awk -F'for ' '{print $2}' | awk '{print $1}' | sed 's/invalid//g')
            rhost=$(echo "$line" | awk -F'from ' '{print $2}' | awk '{print $1}')

            if [ -n "$user" ] && [ -n "$rhost" ]; then
                message="${message}rhost: ${rhost}, user: ${user}"$'\n'
            fi
        fi
    done < "$LOGFILE"
fi

if [[ -n "$message" ]]; then
    echo -e "Invalid User Login Attempts detected:\n\n$message"
    # Mail sender
    # echo -e "$message" | mail -s "$SUBJECT" "$RECIPIENT"
else
    echo "Not detected Invalid User Login Attempt"
fi


