#!/bin/sh
case "$SCFW_TEST_VERSION_CASE" in
  descendants) sleep 30 & wait ;;
  verbose) printf 'uv 0.13.4 '; head -c 100000 /dev/zero ;;
  *) printf 'uv 0.13.4\n' ;;
esac
