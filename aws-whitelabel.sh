#!/bin/bash

W=`dirname $0`/aws-whitelabel.py


while true; do

    $W

    ret=$?


    if [ $ret -eq 2 ]; then

        [ "$DRY_RUN" ] && exit

        echo
        echo
        echo "Waiting 1 minute, then will retry"
        sleep 60

    else
        exit $ret
    fi
done
