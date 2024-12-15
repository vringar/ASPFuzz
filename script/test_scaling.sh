#!/usr/bin/env bash

# This script is used to test the scaling of the ASPFuzz

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <upper_core_count> [sleep_duration]" >&2
    exit 1
fi

if ! [[ $1 =~ ^[0-9]+$ ]]; then
    echo "Error: upper_core_count must be a non-negative integer" >&2
    exit 1
fi
upper_core_count=$1

# Second argument: sleep duration (default: 30m)
sleep_duration=${2:-5m}

# Validate sleep duration
if ! [[ $sleep_duration =~ ^[0-9]+[smhd]$ ]]; then
    echo "Error: sleep_duration must be a valid duration (e.g., 5m, 10s, 1h)" >&2
    exit 1
fi

echo "["
# Loop from 0 to the argument
for ((i=0; i<=upper_core_count; i++)); do
    echo "Running ASPFuzz with $i cores" >&2
    cargo make run -y yaml/mailbox_zen2_experimental.yaml -n $i &>"fuzzer$i.log" &
    echo "Waiting for $sleep_duration" >&2
    sleep "$sleep_duration"
    smem -ac "user pid swap maps vss uss pss rss command" &> "smem$i.txt"
    echo "{"
    awk '/ASPFuzz/ { total +=  $7 } END { print "\"PSS\":", total, "," }' "smem$i.txt"
    pkill -9 aspfuzz
    wait # for cargo make run to finish
    awk '/GLOBAL/ { last = $0 } END { match(last, /exec\/sec: ([0-9.]+k?)/, exec); match(last, /clients: ([0-9]+)/, clients); print "\"Executions/sec\":", exec[1], ",\"Clients\":", clients[1] }' fuzzer$i.log
    # Close JSON object, add comma unless it's the last iteration
    if (( i < upper_core_count )); then
        echo "  },"
    else
        echo "  }"
    fi
done
echo "]"