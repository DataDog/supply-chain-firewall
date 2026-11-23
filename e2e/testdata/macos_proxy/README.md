# Native macOS proxy tests

Suite `macos-proxy` registers `NET-15` for pip and Poetry. Each manager has eight
variants: system proxy, artifact-host bypass, explicit environment proxy, and a
nonmatching NO_PROXY-only environment, each with ALLOW and exact-package BLOCK.

Run on a **disposable GitHub Actions macOS worker** for each required architecture
(amd64 and arm64), with pinned real Python and pip/Poetry, Git, and a release-built
SCFW artifact. In addition to the usual absolute `SCFW_E2E_*` inputs:

- Declare `macos-system-proxy` in the macOS cell's `capabilities`.
- Set `SCFW_E2E_DISPOSABLE_MACOS=1`; the harness also requires
  `GITHUB_ACTIONS=true` and a native Darwin host.
- Set `SCFW_E2E_MACOS_SERVICE` to the active network service **ID**, not its name.
  Read `State:/Network/Global/IPv4` and `State:/Network/Global/IPv6` using
  `/usr/sbin/scutil`; the fixture verifies their `PrimaryService` values agree.
- Provision passwordless `/usr/bin/sudo -n`, Xcode's `xcodebuild`, and
  `/usr/bin/xcrun swiftc`. Missing privileges or tools fail infrastructure checks.
- Run `TestPlan`, `TestDiscover`, and `TestE2E` with
  `SCFW_E2E_SUITES=macos-proxy`, a fresh output path, and a test timeout of at least
  90 minutes. Do not run other host-global network/trust fixtures concurrently.

Linux cells omit this capability. Select `macos-proxy` alongside an applicable
suite such as `upstream-routing` to retain explicit N/A records: the shared runner
intentionally rejects a selection containing only N/A cases.

Go owns discovery, child execution, assertions and evidence. The standalone
`settings.swift` fixture accesses SystemConfiguration because `networksetup` text
output cannot round-trip absent, disabled, empty and authenticated dictionaries.
The fixture compiles in the case directory as the runner user. Only its bounded
settings operations run under sudo. Package managers and SCFW run unprivileged.

The shared `/var/tmp/scfw-e2e-system-settings.lock` advisory lock is held from the
initial snapshot through verified restoration. All future host-global network or
keychain fixtures must take this same lock. It is deliberately not deleted.
The snapshot preserves the full native Proxies protocol, its presence/enabled
state, and the complete effective proxy dictionary as a property list. Applying
fixtures disables PAC, auto discovery and SOCKS, configures both HTTP/HTTPS through
a loopback forwarding recorder, and verifies propagation. Restoration uses a fresh
45-second context even after case timeout, checks durable preferences in a new
session, and waits for the complete original effective dictionary. Any restoration
failure fails the case.

Each scenario first runs a direct native-manager installation using independent
HOME/cache/install paths. The protected phase uses the existing baseline oracle:
SCFW proxy-mode evidence, local policy identity/outcome, real installed metadata
and imports, artifact identity, and interceptor cleanup. Recording proxies forward
unchanged public PyPI bytes and only allow known registry/verifier hosts. The
selected exact package and artifact come from the ordinary live registry discovery;
there is no local package registry or package-manager shim.

Route assertions use only the actual installation command's timestamps. They
prove the selected recorder sees expected registry/artifact traffic and its
competitor does not. Artifact-host bypass still passes registry traffic through
the system proxy. NO_PROXY-only suppresses native discovery even though its value
does not match either public host. ALLOW requires a successful exact install;
BLOCK requires policy denial and no installation, including in outbound bypass
cases. Native controls have separate result summaries, preserving protected BLOCK
outcome and exit status.

Evidence includes Xcode/Swift versions and sudo capability commands, active service
ID, before/applied/restored property lists, both forwarding logs, the shared
preflight's native OS/runtime/manager versions and SCFW checksum, public discovery,
and native/protected command and policy/installed-state evidence.

Native compilation and execution require the future macOS Actions jobs. Linux
harness tests and Darwin Go test-binary cross-compilation do not establish Swift
API compatibility or native system-proxy acceptance.
