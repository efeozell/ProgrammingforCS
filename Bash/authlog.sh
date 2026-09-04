#!/bin/bash

IP_ADDRESS="$1"


# Check for successful logins
echo "Successful logins from $IP_ADDRESS:"
grep "$IP_ADDRESS" /var/log/auth.log | grep 'Accepted' | awk '{print $1,$2,$3}'


# Check for failed logins
echo "Failed logins from $IP_ADDRESS:"
grep "$IP_ADDRESS" /var/log/auth.log | grep 'Failed' | awk '{print $1,$2,$3}'