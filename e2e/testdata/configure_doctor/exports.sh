set -eu
. "$1"
printf '%s\0%s\0' "$SCFW_HOME" "$DD_SITE"
