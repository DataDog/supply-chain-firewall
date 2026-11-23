#!/bin/sh
# Generate fixture-only files; never alter host or worker trust stores.
set -eu
[ "$#" = 2 ] || { echo 'usage: policy-fixture-certificates.sh OUTPUT PUBLIC_CA_BUNDLE' >&2; exit 2; }
output=$1
public_ca=$2
fixtures=$(CDPATH= cd -- "$(dirname -- "$0")/../policy_api" && pwd)
[ ! -e "$output" ] || { echo 'certificate output already exists; retain prior evidence' >&2; exit 2; }
umask 077
mkdir -p "$output"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$fixtures/ca.cnf" -keyout "$output/ca.key" -out "$output/ca.crt" 2> "$output/ca-generation.log"
openssl req -new -newkey rsa:2048 -nodes -config "$fixtures/server.cnf" -keyout "$output/server.key" -out "$output/server.csr" 2> "$output/leaf-generation.log"
openssl x509 -req -days 2 -in "$output/server.csr" -CA "$output/ca.crt" -CAkey "$output/ca.key" -CAcreateserial -extfile "$fixtures/server.cnf" -extensions server -out "$output/server.crt" 2> "$output/signing.log"
openssl verify -CAfile "$output/ca.crt" -verify_hostname api.scfw.test "$output/server.crt" > "$output/verification.log"
if openssl verify -CAfile "$output/ca.crt" -verify_hostname unrelated.scfw.test "$output/server.crt" > "$output/wrong-hostname.log" 2>&1; then
  echo 'fixture certificate unexpectedly trusted for an unrelated host' >&2
  exit 1
fi
cat "$public_ca" "$output/ca.crt" > "$output/ca-bundle.crt"
