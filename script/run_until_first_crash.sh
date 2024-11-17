#!/bin/bash

# Directory to monitor
DIR_TO_CHECK="$(git root)/amd_sp/runs/test/solutions"

# Monitor the folder every second
counter=0
while true; do
    if [ -n "$(ls -A "$DIR_TO_CHECK" 2>/dev/null)" ]; then
        echo "Folder not is empty"
        pkill aspfuzz
        exit 0
    fi
    counter=$((counter+1))
    echo -ne "$counter Folder is empty\r"
    sleep 1
done