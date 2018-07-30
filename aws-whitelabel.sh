#!/bin/bash

W=`dirname $0`/aws-whitelabel.py


while true; do

    $W


    if [ $? -eq 2 ]; then

        [ "$DRY_RUN" ] && exit

        echo
        echo
        echo "Waiting 10 minutes, then will retry"
        sleep 300

    else
        exit $?
    fi
done
