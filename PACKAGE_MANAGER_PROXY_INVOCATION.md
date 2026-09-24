# Package-manager proxy invocation research

This note describes how `scfw proxy` could invoke additional package managers
through its local HTTP CONNECT proxy without modifying a package-manager
configuration file. It is design research only; it does not describe code that
has already been implemented.

The examples use these placeholders:

- `SCFW_PROXY_URL`: an HTTP proxy URL such as `http://127.0.0.1:49152`.
- `SCFW_PROXY_HOST` and `SCFW_PROXY_PORT`: the parsed host and port.
- `SCFW_CA_PEM`: the PEM-encoded SCFW root certificate.
- `SCFW_CA_BUNDLE`: a temporary PEM bundle containing the normal trusted roots
  plus the SCFW root certificate.
- `SCFW_JAVA_TRUSTSTORE`: a temporary PKCS#12 truststore containing the roots
  needed by the child JVM, including the SCFW root.

`SCFW_CA_BUNDLE` is preferable to a file containing only the SCFW CA. A CA-file
environment variable commonly replaces, rather than extends, the default trust
store. A combined bundle therefore keeps direct HTTPS requests made by plugins,
build scripts, and subprocesses working.

## Summary

| Manager | Proxy mechanism | CA mechanism | Configuration-file-free coverage |
| --- | --- | --- | --- |
| Gradle | JVM `http.*` and `https.*` system properties | Temporary JVM truststore | Yes, with special handling for the wrapper and daemon |
| Bundler | `http_proxy`/`https_proxy` | `BUNDLE_SSL_CA_CERT` | Yes |
| NuGet | Proxy environment variables | `SSL_CERT_FILE` on Linux; OS trust elsewhere | Partial on macOS and Windows |
| Conan 2 | Proxy environment variables plus command-line core configuration | `core.net.http:cacert_path` | Yes |
| Go | Proxy environment variables | `SSL_CERT_FILE`, depending on Go version and OS | Version/platform dependent |
| Composer | `http_proxy`/`https_proxy` | `COMPOSER_CAFILE` | Yes |
| Cargo | `CARGO_HTTP_PROXY` | `CARGO_HTTP_CAINFO` | Yes |
| crates.io | Uses Cargo; it is a registry, not a separate package manager | Same as Cargo | No separate adapter is needed |

For all managers, set both upper- and lower-case standard proxy variables and
clear both forms of `NO_PROXY` for the child process. This catches subprocesses
and avoids platform-specific case handling:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
ALL_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
all_proxy=$SCFW_PROXY_URL
no_proxy=
GIT_SSL_CAINFO=$SCFW_CA_BUNDLE
```

`GIT_SSL_CAINFO` matters when a package manager delegates a Git dependency to
the `git` executable. These generic variables are a baseline, not a substitute
for the manager-specific settings below.

## Gradle

Executables: `gradle`, `gradlew`, and `gradlew.bat`.

Gradle documents dependency-download proxies as standard JVM system properties.
The proxy must therefore be supplied as separate host and port values, not as a
single URL. The per-run Gradle arguments should include:

```text
--no-daemon
-Dhttp.proxyHost=$SCFW_PROXY_HOST
-Dhttp.proxyPort=$SCFW_PROXY_PORT
-Dhttps.proxyHost=$SCFW_PROXY_HOST
-Dhttps.proxyPort=$SCFW_PROXY_PORT
-Dhttp.nonProxyHosts=
-Djavax.net.ssl.trustStore=$SCFW_JAVA_TRUSTSTORE
-Djavax.net.ssl.trustStorePassword=$SCFW_JAVA_TRUSTSTORE_PASSWORD
-Djavax.net.ssl.trustStoreType=PKCS12
```

The same `-D` properties should also be appended to `JAVA_OPTS` for the child.
That is required for `gradlew` bootstrap: the wrapper may download the Gradle
distribution before Gradle has processed its command-line arguments. The
command-line copies then reach the JVM that executes the build.

`--no-daemon` is important for an ephemeral random CA. The truststore properties
are immutable JVM properties, and allowing a long-lived daemon to outlive the
proxy run would retain a reference to a temporary truststore. Gradle may still
start a disposable single-use daemon when client and build JVM arguments differ,
but that daemon exits after the invocation.

Do not replace an existing `JAVA_OPTS` value; append the SCFW options. Do not use
`GRADLE_OPTS` alone, because Gradle documents it as applying primarily to the
client JVM rather than the daemon.

Sources:

- [Networking with Gradle](https://docs.gradle.org/current/userguide/networking.html)
- [Gradle command-line system properties](https://docs.gradle.org/current/userguide/command_line_interface.html#sec:environment_options)
- [Gradle build environment variables](https://docs.gradle.org/current/userguide/build_environment.html#sec:gradle_environment_variables)
- [Gradle daemon compatibility and immutable properties](https://docs.gradle.org/current/userguide/gradle_daemon.html#sec:daemon_jvm_criteria)

## Bundler

Executable: `bundle` (and commonly the equivalent `bundler`).

Recommended child environment:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
BUNDLE_SSL_CA_CERT=$SCFW_CA_BUNDLE
SSL_CERT_FILE=$SCFW_CA_BUNDLE
GIT_SSL_CAINFO=$SCFW_CA_BUNDLE
```

`BUNDLE_SSL_CA_CERT` is Bundler's explicit per-process setting for a PEM CA file
or directory. `SSL_CERT_FILE` is useful for Ruby/OpenSSL calls outside Bundler's
own downloader. Proxy variables cover Bundler and RubyGems behavior, while
`GIT_SSL_CAINFO` covers Git-sourced gems fetched by an external `git` process.

Do not set `BUNDLE_IGNORE_CONFIG`: it would avoid reading files, but it would
also discard unrelated user settings and credentials. Environment values
already override Bundler configuration without writing it.

Sources:

- [Bundler configuration and `BUNDLE_SSL_CA_CERT`](https://bundler.io/man/bundle-config.1.html)
- [RubyGems proxy environment variables](https://guides.rubygems.org/command-reference/)

## NuGet

Executables and entry points include `dotnet restore`, restore-capable `dotnet`
commands, `nuget restore`, and `msbuild -t:restore`.

Recommended proxy environment for all variants:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
ALL_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
all_proxy=$SCFW_PROXY_URL
no_proxy=
```

NuGet explicitly supports `http_proxy` and `no_proxy` as environment variables.
Modern .NET's default HTTP proxy additionally recognizes `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`, with lower-case names taking
precedence on case-sensitive systems. Set all of them to prevent an inherited
value from winning.

### Certificate trust

On Linux, add:

```text
SSL_CERT_FILE=$SCFW_CA_BUNDLE
```

.NET uses OpenSSL's file-based trust locations on Linux and documents
`SSL_CERT_FILE` and `SSL_CERT_DIR` for overriding them. This provides a clean,
per-process solution for `dotnet restore` on Linux.

On macOS and Windows, .NET uses the platform certificate stores. There is no
documented NuGet or .NET environment variable that injects an additional root
for one process on those platforms. Consequently, proxy routing is portable,
but HTTPS interception is not configuration-file-free and process-scoped there.
Possible future choices are:

1. support NuGet interception only on Linux;
2. temporarily add the SCFW root to the user's OS trust store and remove it on
   every exit path, which changes external system state and needs careful crash
   recovery; or
3. avoid TLS interception for NuGet on macOS and Windows until a safer runtime
   hook is available.

Disabling TLS certificate validation is not an acceptable alternative.

For observation tests, `dotnet restore --no-http-cache` prevents NuGet's HTTP
cache from hiding requests. It does not bypass the global package cache, so a
temporary `NUGET_PACKAGES` directory may also be needed in tests. Those options
should not be added to normal user invocations because they change cache
behavior.

Sources:

- [NuGet configuration reference](https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file)
- [.NET default HTTP proxy environment variables](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient#configure-an-http-proxy)
- [.NET trusted-root locations on Linux](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#trusted-root-certificate-locations-on-linux)
- [`dotnet restore`](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-restore)

## Conan

Executable: `conan`.

### Conan 2

Use the standard proxy environment and add command-line core configuration to
ensure a user's `global.conf` cannot discard it:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
REQUESTS_CA_BUNDLE=$SCFW_CA_BUNDLE

conan <command> <existing arguments> \
  --core-conf=core.net.http:clean_system_proxy=False \
  --core-conf=core.net.http:no_proxy_match=[] \
  --core-conf=core.net.http:cacert_path=$SCFW_CA_BUNDLE
```

Conan 2 passes proxy configuration to Python Requests. Its
`clean_system_proxy` setting can remove proxy environment variables, so SCFW
must override that setting for the invocation. Clearing `no_proxy_match` keeps
an existing Conan-level exclusion from bypassing SCFW. The explicit
`cacert_path` is stronger than relying on Requests to notice
`REQUESTS_CA_BUNDLE`, although both should be set for subprocesses and recipes.

An alternative is to pass an explicit `core.net.http:proxies` dictionary using
`--core-conf`. That is more authoritative but requires constructing and quoting
a typed Conan value correctly on every platform. The environment-plus-core-conf
approach is less brittle while still overriding the setting that can suppress
environment proxies.

### Conan 1

Conan 1 is legacy, but can be covered without a file write using:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
CONAN_CACERT_PATH=$SCFW_CA_BUNDLE
REQUESTS_CA_BUNDLE=$SCFW_CA_BUNDLE
```

`CONAN_CACERT_PATH` explicitly overrides Conan 1's configured CA path. Existing
Conan 1 proxy configuration needs integration testing because it does not have
Conan 2's general `--core-conf` override mechanism.

Sources:

- [Conan 2 networking configuration](https://docs.conan.io/2/reference/config_files/global_conf.html#networking-confs)
- [Conan 2 `--core-conf`](https://docs.conan.io/2/reference/commands/config.html)
- [Conan 1 environment variables](https://docs.conan.io/1/reference/env_vars.html#conan-cacert-path)

## Go

Executable: `go`, for example `go get`, `go install`, `go mod download`, and the
implicit module downloads performed by `go build` or `go test`.

Recommended child environment:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
SSL_CERT_FILE=$SCFW_CA_BUNDLE
GIT_SSL_CAINFO=$SCFW_CA_BUNDLE
```

The Go HTTP transport recognizes `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
and their lower-case equivalents. `GOPROXY` is unrelated: it chooses a Go module
registry such as `proxy.golang.org`; it does not configure an outbound network
proxy and should be preserved unchanged.

`GIT_SSL_CAINFO` covers module resolution that falls back to an external Git
command. SSH-based Git URLs do not use an HTTPS proxy and cannot be intercepted
by this design.

### Certificate trust matrix

- Linux and Unix systems other than macOS: `SSL_CERT_FILE` overrides the default
  root bundle and is suitable when set to `SCFW_CA_BUNDLE`.
- Go 1.26 and earlier on macOS and Windows: Go uses platform verification and
  does not document `SSL_CERT_FILE` as an override, so there is no portable
  process-only CA injection.
- Go 1.27 and later: `crypto/x509` documents `SSL_CERT_FILE` and `SSL_CERT_DIR`
  overrides on macOS and Windows as well. Because this behavior is versioned,
  SCFW should detect `go version` before relying on it.

As with NuGet, system trust-store mutation would be required for older Go
toolchains on macOS and Windows. `GOINSECURE` is not a substitute because it
disables normal checksum/TLS protections for selected modules.

Sources:

- [Go `ProxyFromEnvironment`](https://pkg.go.dev/net/http#ProxyFromEnvironment)
- [Go system certificate pools](https://pkg.go.dev/crypto/x509#SystemCertPool)
- [Go module configuration](https://go.dev/ref/mod#environment-variables)

## Composer

Executables: `composer` and `php composer.phar`.

Recommended child environment:

```text
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
COMPOSER_CAFILE=$SCFW_CA_BUNDLE
SSL_CERT_FILE=$SCFW_CA_BUNDLE
CURL_CA_BUNDLE=$SCFW_CA_BUNDLE
GIT_SSL_CAINFO=$SCFW_CA_BUNDLE
```

Composer prefers lower-case proxy names but accepts upper-case names in CLI
use. `COMPOSER_CAFILE` is its explicit environment variable for the CA file.
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and `GIT_SSL_CAINFO` cover PHP extensions and
VCS subprocesses used for source installs.

Do not add `--no-plugins` or `--no-scripts` merely to simplify interception;
those flags materially change the requested Composer operation. Network access
started by arbitrary plugins or scripts is best-effort: it is covered only when
the child library or executable honors the inherited proxy and CA variables.

Sources:

- [Composer proxy environment variables](https://getcomposer.org/doc/faqs/how-to-use-composer-behind-a-proxy.md)
- [Composer `COMPOSER_CAFILE`](https://getcomposer.org/doc/03-cli.md#composer-cafile)

## Cargo

Executable: `cargo`, including `cargo add`, `cargo fetch`, `cargo build`, and
`cargo install`.

Recommended child environment:

```text
CARGO_HTTP_PROXY=$SCFW_PROXY_URL
CARGO_HTTP_CAINFO=$SCFW_CA_BUNDLE
CARGO_HTTP_PROXY_CAINFO=$SCFW_CA_BUNDLE
HTTP_PROXY=$SCFW_PROXY_URL
HTTPS_PROXY=$SCFW_PROXY_URL
NO_PROXY=
http_proxy=$SCFW_PROXY_URL
https_proxy=$SCFW_PROXY_URL
no_proxy=
GIT_SSL_CAINFO=$SCFW_CA_BUNDLE
```

`CARGO_HTTP_PROXY` applies to both HTTP and HTTPS requests and has precedence
over Cargo configuration files. `CARGO_HTTP_CAINFO` selects the CA bundle used
to verify the intercepted origin connection. `CARGO_HTTP_PROXY_CAINFO` is
primarily for a TLS connection to an HTTPS proxy; setting it to the same bundle
is harmless even though the current SCFW proxy URL uses `http://`.

Cargo normally handles registry and Git HTTP itself. If the user's existing
configuration enables `net.git-fetch-with-cli`, the generic proxy variables and
`GIT_SSL_CAINFO` cover the spawned Git command. SCFW should not force that mode,
because doing so changes Cargo behavior.

Cargo's `--config` command-line option has higher precedence than environment
variables. If strict non-bypassability is required, SCFW can later inject:

```text
--config "http.proxy=\"$SCFW_PROXY_URL\""
--config "http.cainfo=\"$SCFW_CA_BUNDLE\""
```

These are in-memory configuration overrides and do not write a file. However,
environment variables are the simpler initial design. The adapter should detect
or override user-supplied `--config http.proxy` and `--config http.cainfo`
arguments if routing through SCFW must be mandatory.

Sources:

- [Cargo HTTP proxy and CA configuration](https://doc.rust-lang.org/cargo/reference/config.html#httpproxy)
- [Cargo environment variables](https://doc.rust-lang.org/cargo/reference/environment-variables.html)

## Crates and crates.io

There is no separate official `crates` package-manager executable. A crate is a
Rust package, crates.io is the default registry, and Cargo is the client that
resolves registry metadata and downloads `.crate` archives. The Cargo adapter
therefore covers:

- sparse index metadata from `https://index.crates.io/`;
- crate archive downloads from the registry's configured `dl` endpoint;
- registry API operations such as publish; and
- `cargo install`, which installs executable crates.

No second adapter should be added for “Crates.” If a specific third-party
executable named `crate` or `crates` was intended, its exact project and version
must be identified before defining invocation behavior.

Sources:

- [Cargo registries and crates.io](https://doc.rust-lang.org/cargo/reference/registries.html)
- [Cargo registry index and download endpoint](https://doc.rust-lang.org/cargo/reference/registry-index.html)

## Cross-manager design rules

1. Apply overrides only to the spawned package-manager process and its children.
   Do not mutate the parent process environment.
2. Preserve unrelated user environment values. For option-list variables such
   as `JAVA_OPTS`, append rather than replace.
3. Override every case variant of proxy and bypass variables so inherited values
   cannot silently bypass SCFW.
4. Prefer a combined CA bundle or truststore. Treat any CA variable as replacing
   the platform default unless the tool explicitly documents additive behavior.
5. Keep the proxy URL as `http://127.0.0.1:<port>`. HTTPS destinations still use
   CONNECT and TLS; `https://` in the proxy URL would instead request TLS between
   the package manager and the proxy and has different CA semantics.
6. Do not disable TLS verification to make interception work.
7. Preserve registry selection, credentials, lockfiles, and caches. The proxy
   wrapper should change transport only.
8. Expect no observable request when a manager can satisfy an operation entirely
   from cache. Cache-bypass settings belong in tests and diagnostics, not normal
   transformed invocations.
9. Test both native HTTP stacks and delegated subprocess paths, especially Git
   dependencies, Gradle wrapper bootstrap, Composer source installs, and Cargo's
   optional Git CLI mode.

## Recommended implementation order

The lowest-risk next adapters are Cargo, Composer, Bundler, and Conan 2 because
they expose explicit per-process proxy and CA controls. Gradle is also feasible
but needs wrapper/daemon tests and a temporary JVM truststore. Go and NuGet
should be gated by an explicit platform/toolchain compatibility decision before
being advertised as cross-platform HTTPS interception.
