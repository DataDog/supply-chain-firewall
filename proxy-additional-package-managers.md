# Reverse-proxy invocation notes for additional package managers

This is a design note, not an implementation plan or a claim that these
managers are currently supported. It describes how `scfw proxy -- ...` could
make each package manager use an ephemeral, ecosystem-aware reverse proxy
without permanently changing the user's configuration.

The examples use these placeholders:

```sh
SCFW_PROXY_ORIGIN=http://127.0.0.1:49152
SCFW_ROUTE=$SCFW_PROXY_ORIGIN/<opaque-route-for-the-original-registry>
SCFW_TMP=/path/to/a/per-invocation-temporary-directory
```

Each configured upstream registry needs its own `SCFW_ROUTE`. The route tells
the proxy which original registry to contact. An absolute artifact URL that
points at another origin must instead be rewritten to a separate forward route
that carries an authenticated encoding of its full destination; reusing the
registry route would send it to the wrong host. Temporary files must be unique
to one `scfw proxy` invocation and removed after the child process exits.

Redirects require the same treatment as metadata URLs. SCFW must rewrite every
upstream `Location` header, including every hop in a redirect chain, to a
validated full-destination forward route. A relative location is resolved
against the current upstream URL, not the local SCFW URL. Authorization is
retained only for a same-origin redirect and stripped when the origin changes.

Every local route must contain a per-invocation, high-entropy capability or
require equivalent request authentication. The proxy must validate decoded
destinations against the configured registries and artifact origins learned
from their responses so it cannot become an open forwarder for other local
processes. Registry credentials may be forwarded only to the matching original
origin and must be stripped from cross-origin artifact requests. TLS
verification remains enabled between SCFW and every HTTPS upstream.

The injected setting must also have effective precedence over the user's
original command line and environment. Before execution, each manager adapter
must recognize source-changing flags and higher-precedence environment
variables, then rewrite them to equivalent SCFW routes or reject the command
with a precise error. Merely prepending an option is unsafe when a later option
can override it. When a manager exposes effective configuration, SCFW should
verify it before starting any network-producing phase and fail closed if an
unproxied network source remains. Important examples include:

```text
NuGet:  --source, --configfile, RestoreSources, RestoreConfigFile
Conan:  --remote/-r, --no-remote/-nr, CONAN_HOME, project .conanrc
Cargo:  --config, --registry, --index, CARGO_REGISTRIES_*_INDEX
Gradle: --init-script/-I and repository-changing init/settings plugins
```

Equivalent conflict checks are required for the other managers even when the
generated local config normally has the highest documented precedence.

An HTTP forward-proxy setting such as `HTTP_PROXY` is not sufficient: HTTPS
traffic would normally arrive as an opaque `CONNECT` tunnel, so SCFW could not
read registry metadata or package bodies. The mechanisms below deliberately
make the package manager see SCFW as the registry or repository.

## Summary

| Manager / ecosystem | Preferred process-local mechanism | Persistent user config changed? | Main complication |
| --- | --- | --- | --- |
| Gradle / Maven repositories | `--init-script` | No | Must cover dependency, plugin, buildscript, and included-build repositories |
| Bundler / RubyGems | temporary `BUNDLE_APP_CONFIG` plus source mirrors | No | One mirror per Gemfile source; fallback must be disabled |
| NuGet | generated `NuGet.Config` plus restore option/property | No | Local HTTP and the NuGet v3 service index need special handling |
| Conan 2 | temporary `CONAN_HOME` plus named remotes | No | The home also owns profiles, credentials, and the package cache |
| Go modules | `GOPROXY` and `GONOPROXY` environment variables | No | The checksum database is separate from the module proxy |
| Composer / Packagist | temporary alternate root manifest | No | There is no general install-time repository override |
| Cargo / crates.io | repeated global `--config` source replacements | No | Sparse-index `config.json` controls the crate download URL |
| Crates | Same Cargo configuration | No | crates.io is a Cargo registry, not a separate package manager |

## Gradle

### Invocation

Gradle has no general command-line repository flag. Generate an init script
for the invocation and attach it before the original arguments:

```sh
./gradlew \
  --no-daemon \
  --init-script "$SCFW_TMP/scfw.init.gradle.kts" \
  -Dscfw.proxy.origin="$SCFW_PROXY_ORIGIN" \
  build
```

`--no-daemon` is desirable for this experiment so the build cannot retain
invocation-specific state in a long-lived daemon. It is not essential to the
repository override itself.

The generated init plugin should replace, rather than merely prepend,
repositories in all of these locations:

```text
settings.pluginManagement.repositories
settings.dependencyResolutionManagement.repositories
project.buildscript.repositories
project.repositories
included builds' settings and projects
```

Each original Maven or Ivy repository becomes a distinct local route. For an
HTTP loopback route, every generated `MavenArtifactRepository` or
`IvyArtifactRepository` must explicitly allow the insecure protocol. The
script should fail closed if a build adds a repository after SCFW has applied
the replacement.

The proxy must support the Maven/Ivy repository layout used by the upstream.
It must also rewrite repository-relative or absolute artifact URLs found in
POM, Gradle module metadata, Ivy metadata, and plugin marker responses.

This is the most fragile injection in this list: Gradle settings can execute
arbitrary code, plugins have a separate resolution phase, and TestKit or a
nested Gradle invocation may start a build that did not inherit the init
script. Initial support should therefore prove coverage with integration tests
before claiming that all dependency traffic is intercepted.

The Gradle wrapper itself runs before Gradle can evaluate an init script. An
uncached wrapper distribution can therefore be downloaded from
`distributionUrl` without passing through this repository override. Java
toolchain provisioning can likewise use toolchain-resolver plugins and
download outside ordinary dependency repositories. These flows must be
intercepted separately or rejected when uncached; they are not covered by the
invocation above.

Reference: [Gradle initialization scripts and init plugins](https://docs.gradle.org/current/userguide/init_scripts.html),
[centralized repository declarations](https://docs.gradle.org/current/userguide/centralizing_repositories.html).

## Bundler

### Invocation

Copy the project's existing `.bundle/config`, if present, into a fresh
`BUNDLE_APP_CONFIG` directory so unrelated local settings are retained. Add a
mirror entry for every source declared by the Gemfile or lockfile:

```sh
BUNDLE_APP_CONFIG="$SCFW_TMP/bundle" \
  bundle config set --local \
  mirror.https://rubygems.org "$SCFW_ROUTE"

BUNDLE_APP_CONFIG="$SCFW_TMP/bundle" \
  bundle config set --local \
  mirror.https://rubygems.org.fallback_timeout 0

BUNDLE_APP_CONFIG="$SCFW_TMP/bundle" bundle install
```

A fallback timeout of zero makes Bundler accept the configured mirror without
probing it first. That matters because a failed probe must not make Bundler
bypass SCFW and contact the original source.

Do not use `mirror.all` unless all configured sources can safely share one
upstream route. Private sources, source-specific credentials, and different
RubyGems servers require separate mappings. Git dependencies in a Gemfile are
not RubyGems registry downloads and will not be intercepted by this mechanism.

Reference: [Bundler mirror and `BUNDLE_APP_CONFIG` configuration](https://bundler.io/v2.3/man/bundle-config.1.html).

## NuGet

### Invocation

For a simple HTTPS proxy endpoint, `dotnet restore` can override every
configured source with repeated `--source` options:

```sh
dotnet restore \
  --source "$SCFW_ROUTE/v3/index.json" \
  --no-http-cache
```

For the experiment's HTTP loopback listener, prefer a generated
`NuGet.Config`. Preserve relevant credentials, source mappings, trusted
signers, and other restore settings, but clear and recreate `packageSources`.
Keep each original source name so `packageSourceMapping` continues to work:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org"
         value="http://127.0.0.1:49152/route/nuget/v3/index.json"
         protocolVersion="3"
         allowInsecureConnections="true" />
  </packageSources>
</configuration>
```

Then pass that file only to the child operation:

```sh
dotnet restore --configfile "$SCFW_TMP/NuGet.Config" --no-http-cache
nuget restore Solution.sln -ConfigFile "$SCFW_TMP/NuGet.Config" -NoHttpCache
msbuild -restore -p:RestoreConfigFile="$SCFW_TMP/NuGet.Config"
```

Commands such as `dotnet build`, `test`, `run`, `publish`, and `pack` may run an
implicit restore. Their long-form restore options can be injected where the
command supports them; otherwise SCFW can perform an explicit proxied restore
and append `--no-restore` to the original command. MSBuild-based operations can
use the `RestoreConfigFile` property.

The local endpoint must be a valid NuGet v3 service index. Every resource URL
inside the service-index response must point through SCFW too; changing only
the index URL is not sufficient. `--no-http-cache` avoids the HTTP cache, but
the global packages folder can still satisfy a restore without network access.
Using a temporary `NUGET_PACKAGES` is useful for an interception test, but
should not silently change normal command semantics.

Reference: [`dotnet restore`](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-restore),
[`NuGet.Config`](https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file),
[NuGet HTTP-source enforcement](https://learn.microsoft.com/en-us/nuget/consume-packages/nuget-https-everywhere),
[NuGet restore through MSBuild](https://learn.microsoft.com/en-us/nuget/reference/msbuild-targets).

## Conan 2

### Invocation

Conan accepts a remote name on `conan install`, not a remote URL. Create a
per-invocation Conan home, seed it with the effective profiles and required
configuration, and add one named local remote per original remote:

```sh
CONAN_HOME="$SCFW_TMP/conan" \
  conan remote add scfw-conancenter "$SCFW_ROUTE"

CONAN_HOME="$SCFW_TMP/conan" \
  conan install . --remote=scfw-conancenter
```

If the original operation can consult several remotes, retain their order and
pass each generated remote name:

```sh
CONAN_HOME="$SCFW_TMP/conan" \
  conan install . \
  --remote=scfw-private \
  --remote=scfw-conancenter
```

`CONAN_HOME` also selects the package cache. To preserve cache-hit behavior,
the temporary home must begin as a per-invocation snapshot or copy-on-write
clone of the effective Conan home, including profiles, settings, hooks,
plugins, certificates, credentials, global configuration, recipes, and binary
packages. A brand-new empty home can cause downloads or builds that the
original command would not perform and is only acceptable as an explicitly
documented test mode. Pointing the temporary configuration at the live cache
is also unsafe because Conan documents that its cache is not concurrent. The
snapshot operation therefore needs coordination that prevents it from racing
another writer; if SCFW cannot obtain a safe snapshot, it must fail rather
than claim semantic equivalence.

A project `.conanrc` can override `CONAN_HOME`, so SCFW should check `conan
config home` after setting the environment and fail closed if it did not
select the temporary home.

The proxy must implement the Conan remote API used by the detected Conan
version and route both recipes and binary packages. Cached recipes and binaries
may mean that a normal install makes no network calls; forcing `--update` would
change resolution semantics and should not be done automatically.

This covers installs of cached or prebuilt binaries only. If Conan is allowed
to build a missing binary, a recipe's `source()` method can download archives
from arbitrary URLs outside every configured Conan remote. Until SCFW has a
separate way to intercept those recipe-controlled downloads, the adapter must
reject explicit `--build` options and fail closed when the effective build
policy would build a dependency instead of downloading a binary.

Reference: [Conan remote commands](https://docs.conan.io/2/reference/commands/remote.html),
[`conan install`](https://docs.conan.io/2/reference/commands/install.html),
[`CONAN_HOME`](https://docs.conan.io/2/reference/environment.html),
[`remotes.json`](https://docs.conan.io/2/reference/config_files/remotes.html).

## Go modules

### Invocation

Go provides the cleanest process-local override in this set:

```sh
GOPROXY="$SCFW_ROUTE" \
GONOPROXY=none \
go mod download
```

The same environment applies to module resolution done by `go build`, `go
test`, `go get`, and `go install`. Use exactly one proxy URL: appending
`,direct`, `|direct`, or another upstream would provide a bypass. Explicitly
setting `GONOPROXY=none` prevents `GOPRIVATE` defaults from sending private
modules directly to their version-control hosts. Do not use `go env -w`, which
would persist the change.

SCFW must implement the Go module proxy protocol, including `@v/list`,
`@latest`, and versioned `.info`, `.mod`, and `.zip` endpoints. The module cache
can satisfy requests without network traffic; a temporary `GOMODCACHE` is
appropriate for an interception test, not as an invisible production default.

The public checksum database is a separate network service. `GOPROXY` does not
redirect `sum.golang.org`. The choices are:

1. leave checksum verification enabled and accept that checksum traffic is not
   package-download traffic through SCFW;
2. proxy the checksum database separately; or
3. set `GOSUMDB=off`, which weakens integrity verification and is therefore not
   recommended.

Reference: [Go modules and the `GOPROXY` protocol](https://go.dev/ref/mod).

## Composer

### Invocation

Composer has no general `install` or `update` option that replaces all
repositories. Its `--repository` option applies to commands such as
`create-project`, not ordinary dependency installation.

For an install experiment, create an alternate root manifest beside the real
one, copy and rewrite the matching lockfile, replace each network repository
with its SCFW route, and disable implicit Packagist unless it also has a route:

```sh
COMPOSER=.scfw-composer.json composer install
```

The temporary manifest should conceptually contain:

```json
{
  "repositories": [
    { "type": "composer", "url": "http://127.0.0.1:49152/route/packagist" },
    { "packagist.org": false }
  ],
  "config": {
    "secure-http": false
  }
}
```

All other fields come from the real root manifest. `secure-http=false` is
needed only because the experimental listener is HTTP; a trusted local HTTPS
listener would avoid that relaxation. The proxy must rewrite `dist.url` and
any other absolute download URLs in Composer metadata.

The copied lockfile also needs every locked `dist.url` rewritten to a
full-destination SCFW forward route. `composer install` consumes the locked
package records directly and may never query the repository metadata again.
Locked `source.url` entries invoke a VCS client and should fail closed unless
SCFW deliberately supports that transport; silently leaving them unchanged
would bypass the package proxy.

There are important limits:

- `COMPOSER` changes the lockfile basename too, so `composer.lock` must be
  copied to `.scfw-composer.lock` and its download URLs rewritten before
  `install` to preserve locked resolution without bypassing SCFW.
- `update`, `require`, and `remove` are expected to update the real manifest or
  lockfile. Running them against an alternate manifest would hide those
  changes. Transparent support for mutating commands therefore needs either a
  Composer plugin or a journaled edit-and-restore/merge strategy; invocation
  flags alone are insufficient.
- Root-level VCS, package, path, and artifact repositories are not equivalent
  to a Composer repository and cannot blindly be replaced. VCS and source
  downloads may invoke Git, Mercurial, or Subversion outside the registry
  proxy.
- A temporary `COMPOSER_HOME/config.json` can add global repositories, but the
  project's own repository declarations take precedence. It cannot guarantee
  that every configured source is intercepted.

Reference: [Composer CLI and the `COMPOSER` variable](https://getcomposer.org/doc/03-cli.md),
[Composer repository behavior](https://getcomposer.org/doc/05-repositories.md),
[Composer root manifest schema](https://getcomposer.org/doc/04-schema.md).

## Cargo

### Invocation

Cargo supports arbitrary process-local configuration with repeatable global
`--config` options. Replace crates.io with a local sparse registry before the
original subcommand:

```sh
cargo \
  --config 'source.crates-io.replace-with="scfw-crates-io"' \
  --config 'source.scfw-crates-io.registry="sparse+http://127.0.0.1:49152/route/crates-io/"' \
  fetch
```

The `sparse+` prefix and final slash are significant. The same global options
can precede `build`, `test`, `check`, `run`, or `install`.

For every alternate registry used by `Cargo.toml`, generate an equivalent
source replacement and a distinct SCFW route. Source replacement is preferable
to changing the registry identity because Cargo expects the replacement to be
an exact mirror of the original source and can retain the original source
identity in dependency resolution.

Authenticated alternate registries need additional configuration. The local
replacement has a different source URL, so Cargo may not apply the credential
provider or token associated with the original registry. SCFW must either
configure the replacement as an authenticated named registry with an
invocation-scoped credential provider, or authenticate upstream itself after
looking up the original registry's credentials. In the latter design, the
local `config.json` should describe the authentication behavior expected by
Cargo, and upstream credentials must never be forwarded to another origin.

The sparse index root serves `config.json`. Its `dl` field determines where
Cargo downloads each `.crate` file, so SCFW must rewrite `dl` to its local
route. The optional `api` field is used for registry operations such as
publishing and should either be routed deliberately or omitted for this
install-only experiment.

Git dependencies are separate Cargo sources and are not covered by a crates.io
replacement. The Cargo cache may also avoid network calls. A temporary
`CARGO_HOME` is useful for an interception test but would also hide the user's
credentials and cached packages, so it should not be the normal injection
mechanism.

Reference: [Cargo command-line configuration overrides](https://doc.rust-lang.org/cargo/reference/config.html),
[source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html),
[registry index and download protocol](https://doc.rust-lang.org/cargo/reference/registry-index.html).

## Crates

There is no separate official package manager named **Crates** in the Rust
toolchain. A crate is the package artifact, crates.io is Cargo's default
registry, and Cargo is the client. Therefore the Cargo invocation above is also
the crates.io invocation:

```sh
cargo \
  --config 'source.crates-io.replace-with="scfw-crates-io"' \
  --config 'source.scfw-crates-io.registry="sparse+http://127.0.0.1:49152/route/crates-io/"' \
  install ripgrep
```

If “Crates” refers to a third-party executable rather than crates.io, it needs
to be identified separately; it should not be modeled as another ecosystem on
the basis of its name alone.

Reference: [Cargo registries](https://doc.rust-lang.org/cargo/reference/registries.html).

## Recommended order for an eventual experiment

```text
Go
  -> Cargo / crates.io
  -> Bundler
  -> NuGet
  -> Conan
  -> Gradle
  -> Composer
```

Go and Cargo have strong process-local controls. Bundler and NuGet have
well-defined mirror/config mechanisms. Conan is feasible but its home directory
owns much more than remotes. Gradle requires lifecycle-wide repository
enforcement, and Composer cannot transparently preserve mutating-command
behavior with invocation flags alone.
