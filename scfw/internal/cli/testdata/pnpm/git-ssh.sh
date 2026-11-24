#!/bin/sh
# Fake ssh for the pnpm git+ssh tests: serve the requested git-upload-pack
# from the repository root named by SCFW_TEST_SSH_ROOT, without a network.
for argument in "$@"; do
	case $argument in
	"git-upload-pack"*)
		repo=$(printf '%s' "$argument" | cut -d"'" -f2)
		exec git upload-pack "$SCFW_TEST_SSH_ROOT$repo"
		;;
	esac
	done
echo "unexpected ssh request: $*" >&2
exit 1
