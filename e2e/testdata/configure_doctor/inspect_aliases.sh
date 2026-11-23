set -eu
. "$1"
alias npm
if alias pip >/dev/null 2>&1; then exit 1; fi
