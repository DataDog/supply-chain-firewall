#!/bin/sh
set -eu
[ "${SCFW_E2E_POLICY_WORKER:-}" = disposable ] || { echo 'disposable policy worker required' >&2; exit 2; }
: "${SCFW_E2E_OUTPUT:?}" "${SCFW_E2E_TEST_BINARY:?}" "${SCFW_E2E_POLICY_TLS:?}"
mkdir -p "$SCFW_E2E_OUTPUT"
sh testdata/system/policy-fixture-certificates.sh "$SCFW_E2E_POLICY_TLS" /etc/ssl/certs/ca-certificates.crt
uname -a > "$SCFW_E2E_OUTPUT/worker-uname.txt"
git --version > "$SCFW_E2E_OUTPUT/worker-git.txt"
dpkg-query -W git ca-certificates openssl > "$SCFW_E2E_OUTPUT/worker-packages.txt"
"$SCFW_E2E_TEST_BINARY" -test.run '^TestPlan$' -test.v > "$SCFW_E2E_OUTPUT/plan.log" 2>&1
if [ ! -f "$SCFW_E2E_DISCOVERY" ]; then
  "$SCFW_E2E_TEST_BINARY" -test.run '^TestDiscover$' -test.v > "$SCFW_E2E_OUTPUT/discover.log" 2>&1
fi
cp "$SCFW_E2E_DISCOVERY" "$SCFW_E2E_OUTPUT/discovery-input.json"
"$SCFW_E2E_TEST_BINARY" -test.run '^TestE2E$' -test.v -test.timeout=20m > "$SCFW_E2E_OUTPUT/e2e.log" 2>&1
