#!/bin/bash

get_listening_ports() {
        ss -tuln | awk 'NR>1 && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:/ {split($5, a, ":"); print a[2]}' | sort -nu
}

get_process_for_port() {
        local port=$1
        local pid=$(lsof -ti :"$port" 2>/dev/null | head -n1)
        if [[ -z "$pid" ]]; then
                echo "Port: $port, Process: (not found)"
                return
        fi
        local process=$(ps -p "$pid" -o comm= 2>/dev/null)
        echo "Port: $port, Process: ${process:-unknown} (PID: $pid)"

}

echo "Open ports on $(hostname):"
echo "====================="

listening_ports=$(get_listening_ports)

for port in $listening_ports; do
        get_process_for_port "$port"
done