#!/bin/sh
# Git runs "$GIT_SSH_COMMAND [options] host command"; run the command locally.
[ "$1" = -G ] && exit 0
for command; do :; done
exec sh -c "$command"
