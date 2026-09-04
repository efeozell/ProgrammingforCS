#!/bin/bash

#This method take one parameter ip, with this parameter send request abuseipdb API and this API
#responsed a report and we take this report and print on the screen

API_KEY="MUST_BE_FILLED"

get_abuse_report() {
        local ip="$1"

        if [[ -z "$ip" ]];then
                echo "Error: Please enter a IP Address." >&2
                echo "Usage: $0 <IP_ADDRESS> ">&2
        else

                local result=$(curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90" \
                        -H "Key: ${API_KEY}" \
                        -H "Accept: application/json")

                echo "$result"
        fi
}


analyze_report() {
        local report="$1"

        if [[ -z "$report" ]]; then return; fi



        local ip=$(echo "$report" | jq -r '.data.ipAddress')
        local abuse_confidene_score=$(echo "$report" | jq -r '.data.abuseConfidenceScore')
        local is_suspicious=false

        if [[ $abuse_confidence_score -gt 50 ]]; then
                is_suspicious=true
        fi

        echo "IP: $ip"
        echo "Abuse Confidence Score: $abuse_confidene_score"
        if $is_suspicious; then
                echo "Suspicious IP address detected: $ip"
                # We can add alarm here
        fi
}

last_logins=$(last -i | awk '!/wtmp/ && !/tty/ && !/boot/ {print $3}' | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq)
for ip in $last_logins; do
        report=$(get_abuse_report "$ip")
        analyze_report "$report"
done