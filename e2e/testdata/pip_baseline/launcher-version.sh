#!/bin/sh
# Offline harness control: exercise launcher selection without a registry install.
case "${0##*/}" in
    pip)
        [ "$1" = "--version" ] || exit 99
        printf 'pip 26.2.2 from /fixture/pip (python 3.12)\n'
        ;;
    pip3)
        [ "$1" = "--version" ] || exit 99
        printf 'pip %s from /fixture/pip3 (python 3.12)\n' "$SCFW_HARNESS_PIP3_VERSION"
        exit "${SCFW_HARNESS_PIP3_EXIT:-0}"
        ;;
    python|git)
        exit 0
        ;;
    scfw)
        exit 42
        ;;
    *)
        exit 99
        ;;
esac
