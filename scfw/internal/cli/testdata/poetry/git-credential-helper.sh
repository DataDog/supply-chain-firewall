#!/bin/sh
if [ "$1" = get ]; then
    printf 'username=private\npassword=git-secret\n'
fi
