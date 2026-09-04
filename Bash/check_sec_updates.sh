#!/bin/bash

HOSTNAME=$(hostname)
BOT_TOKEN="MUST_BE_FILL"
CHAT_ID="MUST_BE_FILL"

send_telegram_alert() {
        local message="$1"

        curl -s -X POST \
        "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        --data-urlencode "text=${message}" \
        > /dev/null
}


check_security_updates() {
        security_updates=$(apt list --upgradable 2>/dev/null | grep -i security)
        if [[ -n $security_updates ]]; then
                message="Pending security updates detected:\n$security_updates"
                send_telegram_alert "$message"
                echo "Telegram Message Successfully sent it with upgradable application informations"

        else
                echo "No upgradable application found on the Ubuntu Server"
        fi

}

check_security_updates