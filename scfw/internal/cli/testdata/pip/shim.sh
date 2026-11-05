#!/bin/sh
if [ "$1" = "debug" ]; then
    printf 'debug\n' >> "$SCFW_TEST_PIP_DEBUG_COUNT"
fi
exec "$SCFW_TEST_PIP_EXECUTABLE" "$@"
