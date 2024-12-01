#!/bin/bash

RESULT_COUNT=1
TEST_NAME="test"
if [ -n "$1" ]; then
    RESULT_COUNT="$1"
fi
if [ -n "$2" ]; then
    TEST_NAME="$2"
fi

# Directory to monitor
DIR_TO_CHECK="$(git rev-parse --show-toplevel)/amd_sp/runs/$TEST_NAME/solutions"

# Function to count items in the folder
count_items_in_folder() {
    ls -A "$DIR_TO_CHECK" 2>/dev/null | wc -l
}

# Monitor the folder every second
counter=0
while true; do
    tput clear
    echo "Checking $DIR_TO_CHECK"
    item_count=$(count_items_in_folder)
    if [ "$item_count" -ge $RESULT_COUNT ]; then
        echo "Folder not is empty"
        pkill aspfuzz
        exit 0
    fi
    if rg -e "Assertion" fuzzer.log &>/dev/null; then
        echo "Assertion hit"
    fi
    if rg -e "Blocked" fuzzer.log &>/dev/null; then
        echo "Blocked reentrant IO"
    fi
    counter=$((counter + 1))
    echo -ne "$counter Folder contain $item_count files \n"
    python ./script/metadata_classifier.py $TEST_NAME
    sleep 5
done
