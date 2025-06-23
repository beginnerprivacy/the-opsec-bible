#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "XMR address replacement script."
    echo "Usage: $0 <old_xmr_address> <new_xmr_address>"
    exit 1
fi

len1=${#1}
len2=${#2}

if [ "$len1" -ne 95 ] || [ "$len2" -ne 95 ]; then
    echo "Invalid XMR address."
    exit 1
fi

OLD_ADDRESS="$1"
NEW_ADDRESS="$2"

find "$(dirname -- "$0")"/../docs/opsec -name "*.md" -type f -exec sed -i "s|${OLD_ADDRESS}|${NEW_ADDRESS}|g" {} +

echo "XMR address updated."
