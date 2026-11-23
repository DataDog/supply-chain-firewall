#!/bin/sh
# Run only an ephemeral container; DNS and fixture trust never modify the host.
set -eu
[ "$#" = 4 ] || { echo 'usage: policy-fixture-worker.sh IMAGE CHECKOUT MANAGER_ROOT TOOL_ROOT' >&2; exit 2; }
image=$1
checkout=$2
managers=$3
tools=$4
: "${SCFW_E2E_OUTPUT:?}" "${SCFW_E2E_MATRIX:?}" "${SCFW_E2E_DISCOVERY:?}" "${SCFW_E2E_CELL:?}" "${SCFW_E2E_BINARY:?}" "${SCFW_E2E_TEST_BINARY:?}"
[ ! -e "$SCFW_E2E_OUTPUT" ] || { echo 'output exists; preserve evidence and select a new path' >&2; exit 2; }
mkdir -p "$SCFW_E2E_OUTPUT"
name="scfw-policy-$(id -u)-$$"
sha256sum /etc/hosts > "$SCFW_E2E_OUTPUT/host-hosts-before.sha256"
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then sha256sum /etc/ssl/certs/ca-certificates.crt > "$SCFW_E2E_OUTPUT/host-ca-before.sha256"; fi
cleanup() {
  code=$?
  trap - EXIT HUP INT TERM
  docker rm -f "$name" > "$SCFW_E2E_OUTPUT/docker-cleanup.log" 2>&1 || true
  removed=true
  if remaining=$(docker ps -a --filter "name=^/$name$" --format '{{.ID}}'); then
    if [ -n "$remaining" ]; then removed=false; code=1; fi
  else removed=false; code=1
  fi
  sha256sum /etc/hosts > "$SCFW_E2E_OUTPUT/host-hosts-after.sha256"
  cmp "$SCFW_E2E_OUTPUT/host-hosts-before.sha256" "$SCFW_E2E_OUTPUT/host-hosts-after.sha256" || code=1
  if [ -f "$SCFW_E2E_OUTPUT/host-ca-before.sha256" ]; then
    sha256sum /etc/ssl/certs/ca-certificates.crt > "$SCFW_E2E_OUTPUT/host-ca-after.sha256"
    cmp "$SCFW_E2E_OUTPUT/host-ca-before.sha256" "$SCFW_E2E_OUTPUT/host-ca-after.sha256" || code=1
  fi
  printf '{"container_removed":%s,"exit_code":%s}\n' "$removed" "$code" > "$SCFW_E2E_OUTPUT/worker-cleanup.json"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
docker image inspect "$image" --format '{{.Id}}' > "$SCFW_E2E_OUTPUT/worker-image.txt"
docker run --rm --name "$name" --hostname scfw-policy-worker --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --sysctl net.ipv4.ip_unprivileged_port_start=0 --add-host api.scfw.test:127.0.0.1 \
  --mount "type=bind,src=$checkout,dst=$checkout,readonly" \
  --mount "type=bind,src=$managers,dst=$managers,readonly" \
  --mount "type=bind,src=$tools,dst=$tools,readonly" \
  --mount "type=bind,src=$SCFW_E2E_OUTPUT,dst=$SCFW_E2E_OUTPUT" \
  --workdir "$checkout/e2e" \
  --env SCFW_E2E_POLICY_WORKER=disposable --env "SCFW_E2E_POLICY_TLS=$SCFW_E2E_OUTPUT/tls" \
  --env SCFW_E2E_SUITES=policy-api --env SCFW_E2E_OUTPUT --env SCFW_E2E_MATRIX --env SCFW_E2E_DISCOVERY --env SCFW_E2E_CELL --env SCFW_E2E_BINARY --env SCFW_E2E_TEST_BINARY \
  "$image" /bin/sh testdata/system/policy-fixture-entrypoint.sh
