#!/bin/sh
set -eu
[ "$0" = "$SCFW_TEST_PYTHON_RUNTIME" ] || exit 97
[ "$#" -eq 6 ] || exit 98
[ "${1##*/}" = inspect_cache.py ] || exit 99
[ "$2" = "$PIP_CACHE_DIR" ] || exit 100
printf '{"%s":{"present":true,"sha256":"%s"},"%s":{"present":true,"sha256":"%s"}}\n' "$4" "$SCFW_TEST_ROOT_SHA" "$6" "$SCFW_TEST_LEAF_SHA"
