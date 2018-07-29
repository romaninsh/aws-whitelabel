#!/bin/bash

while true; do

    ./aws-whitelabel.py

    if [ $? = 2 ]; then
        echo
        echo
        echo "Waiting 10 minutes, then will retry"
        sleep 300

    else
        break
    fi
done
