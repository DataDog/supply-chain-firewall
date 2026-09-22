# Supply Chain Firewall

![Build](https://github.com/DataDog/supply-chain-firewall/actions/workflows/build.yml/badge.svg)
![Test](https://github.com/DataDog/supply-chain-firewall/actions/workflows/test.yml/badge.svg)
![Code quality](https://github.com/DataDog/supply-chain-firewall/actions/workflows/code-quality.yml/badge.svg)

<p align="center">
  <img src="https://github.com/DataDog/supply-chain-firewall/blob/v4/images/logo.png?raw=true" alt="Supply Chain Firewall" width="300" />
</p>

> [!NOTE]
> The Python version of SCFW is deprecated and is maintained only for security updates. It remains available on the [`v3` branch](https://github.com/DataDog/supply-chain-firewall/tree/v3).

Supply Chain Firewall (SCFW) is a command-line tool for preventing the installation of malicious npm and PyPI packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

Given a command for a supported package manager, Supply Chain Firewall collects all package targets that would be installed by the command and evaluates them against Datadog Security Research's threat intelligence feed on known-malicious and compromised open source packages. It also applies custom policy rules configured within your Datadog organization under the [Datadog Code Security](https://www.datadoghq.com/product/code-security/) integration with Supply Chain Firewall. The command is allowed or blocked from running on the basis of this policy evaluation. In cases where only warning-level findings are indicated, they are presented to the user along with a prompt confirming intent to proceed with the command.

---
### Interested in SCFW for your business use-case? [Enroll](https://docs.google.com/forms/d/1Xqh5h1n3-jC7au2t30fdTq732dkTJqt_cb7C7T-AkPc/edit) as a design partner.
---

## Getting started

### Installation

Supply Chain Firewall is distributed as a single Go binary with no runtime dependencies.

#### Github release

Download the binary for your operating system and architecture from the [latest GitHub release](https://github.com/DataDog/supply-chain-firewall/releases/latest). Before running these commands, replace the value of `scfw_expected_checksum` with the SHA-256 checksum published for that binary on the release page:

```bash
# Replace this placeholder with the checksum from the release page.
$ scfw_expected_checksum="<expected-sha256-checksum>"

# Detect the operating system used in the release artifact name.
$ case "$(uname -s)" in
    Darwin) scfw_os=darwin ;;
    Linux)  scfw_os=linux ;;
    *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
  esac

# Detect the CPU architecture used in the release artifact name.
$ case "$(uname -m)" in
    x86_64)        scfw_arch=amd64 ;;
    arm64|aarch64) scfw_arch=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac

# Download the binary for the detected platform.
$ scfw_binary="scfw-${scfw_os}-${scfw_arch}"
$ curl -fLO "https://github.com/DataDog/supply-chain-firewall/releases/latest/download/${scfw_binary}"

# Calculate the downloaded binary's checksum.
$ scfw_actual_checksum=$(sha256sum "${scfw_binary}" | awk '{print $1}')

# Stop if the downloaded binary does not match the published checksum.
$ if [ "${scfw_actual_checksum}" != "${scfw_expected_checksum}" ]; then
    echo "Checksum verification failed" >&2
    exit 1
  fi

# Install the verified binary in a directory on PATH.
$ chmod +x "${scfw_binary}"
$ sudo install "${scfw_binary}" /usr/local/bin/scfw
```

#### Through go install

If Go 1.26 or later is installed, install SCFW with `go install`:

```bash
$ go install github.com/DataDog/supply-chain-firewall/scfw@latest
```

This installs the `scfw` binary to `$(go env GOPATH)/bin`; be sure that directory is on your `PATH`.

To check whether the installation succeeded, run the following command and verify that you see output similar to the following.

```bash
$ scfw --help
Supply Chain Firewall, a tool for preventing the installation of malicious software packages.

Usage:
  scfw [command]

Available Commands:
  configure   Configure the environment for using Supply Chain Firewall.
  proxy       Run a package manager through an experimental local registry proxy.
  run         Run a package manager command through Supply Chain Firewall.
...
```

### Post-installation steps

To get the most out of Supply Chain Firewall, it is strongly recommended to run the `scfw configure` command after installation to configure the environment with necessary Datadog credentials. Via this command, users can also ensure that all commands for supported package managers are passively run through `scfw`.

```bash
$ scfw configure \
    --dd-api-key=<your-api-key> \
    --dd-app-key=<your-app-key> \
    --dd-site=<your-dd-site> \
    --alias-npm \
    --alias-yarn \
    --alias-pnpm \
    --alias-bun \
    --alias-pip \
    --alias-poetry \
    --alias-uv
```

When passing these values via shell variables, e.g. in scripts, prefer this `=` form: `--dd-api-key=$DD_API_KEY --dd-app-key=$DD_APP_KEY --dd-site=$DD_SITE`.

This does two things:

1. Stores your Datadog API key and application key securely in your system's keychain, so credentials don't need to be kept in plaintext or supplied on every command.
2. Adds shell aliases to your `.bashrc`, `.bash_profile`, `.zshrc`, and `.zprofile` (whichever already exist) so that npm, Yarn, pnpm, Bun, pip, Poetry, and/or uv transparently run through `scfw proxy`. Every command receives process-local registry configuration; registry requests are forwarded through the proxy, while commands that make no registry requests run normally. Restart your shell (or source the relevant rc file) for the aliases to take effect.

`scfw configure` is idempotent and may be re-run at any time to change your configuration. Alias options are additive, so aliases configured by an earlier invocation remain in place unless their corresponding `--remove-alias-*` option is passed. The command manages its own clearly indicated block of your shell rc files and never touches anything else you've added.

Available `configure` options:

| Flag | Description |
| --- | --- |
| `--dd-api-key` | Datadog API key used for policy evaluation and reporting. |
| `--dd-app-key` | Datadog application key used for policy evaluation and reporting. |
| `--dd-site` | Datadog site parameter used for policy evaluation and reporting (default: `datadoghq.com`). |
| `--alias-npm` | Add a shell alias to run npm through `scfw proxy`. |
| `--remove-alias-npm` | Remove the npm shell alias managed by `scfw`. |
| `--alias-yarn` | Add shell aliases for Yarn's `yarn` and `yarnpkg` executables. |
| `--remove-alias-yarn` | Remove the Yarn shell aliases managed by `scfw`. |
| `--alias-pnpm` | Add a shell alias to run pnpm through `scfw proxy`. |
| `--remove-alias-pnpm` | Remove the pnpm shell alias managed by `scfw`. |
| `--alias-bun` | Add a shell alias to run Bun through `scfw proxy`. |
| `--remove-alias-bun` | Remove the Bun shell alias managed by `scfw`. |
| `--alias-pip` | Add shell aliases to run pip/pip3 through `scfw proxy`. |
| `--remove-alias-pip` | Remove the pip/pip3 shell aliases managed by `scfw`. |
| `--alias-poetry` | Add a shell alias to run Poetry through `scfw proxy`. |
| `--remove-alias-poetry` | Remove the poetry shell alias managed by `scfw`. |
| `--alias-uv` | Add a shell alias to run uv through `scfw proxy`. |
| `--remove-alias-uv` | Remove the uv shell alias managed by `scfw`. |
| `--scfw-home` | Directory Supply Chain Firewall can use as a local cache. |
| `--remove` | Remove all Supply Chain Firewall managed configuration. |

When inspecting package manager commands, Datadog credentials and the Datadog site parameter may alternatively be provided via environment variables `DD_API_KEY`, `DD_APP_KEY`, and `DD_SITE`, respectively. This is particularly useful in CI environments where secrets are injected per job. Environment variables always take precedence over stored credentials sourced from the system keychain.

### Compatibility and limitations

|  Package manager  |   Supported versions  |        Inspected subcommands       |
| :---------------: | :-------------------: | :--------------------------------: |
| npm               | >= 7.0                | `install` (including aliases)      |
| pip               | >= 22.2               | `install`                          |
| poetry            | >= 1.7                | `add`, `install`, `sync`, `update` |

Supply Chain Firewall may only know how to inspect some of the "installish" subcommands for its supported package managers. These are shown in the above table. Any other subcommands are always allowed to run.

Note that `scfw` will refuse to run inspected subcommands on an unsupported version of a supported package manager. In order to get the most out of `scfw`, please verify that you are running a supported version of your package manager and upgrade accordingly before using this tool.

### Uninstalling Supply Chain Firewall

Before uninstalling, be sure to run `scfw configure --remove` to remove any Supply Chain Firewall-managed configuration you may have previously added to your environment.

```bash
$ scfw configure --remove
```

Then remove the `scfw` binary, e.g. by deleting it from `$(go env GOPATH)/bin` if it was installed via `go install`.

## Usage

To inspect a package manager command with Supply Chain Firewall, prepend `scfw run --` to the command you intend to run:

```
$ scfw run -- npm install react
added 1 package in 226ms

$ scfw run -- pip install some-evil-package
Package some-evil-package-1.0.0:
  - Datadog Security Research has determined that package some-evil-package-1.0.0 is malicious.

The command was blocked. No changes have been made.
```

Once a package manager's shell alias has been configured, an explicit `scfw proxy --` prefix is no longer needed. Every invocation uses the registry proxy. The ecosystem handler evaluates recognized distribution downloads, while metadata, authentication, publishing, and unrecognized registry requests are forwarded without policy evaluation.

`scfw run` supports the following options:

| Flag | Description |
| --- | --- |
| `--executable` | Package manager executable to use for running commands (default: environmentally determined). |
| `--error-on-block` | Treat blocked commands as errors, i.e. exit non-zero (useful for scripting and CI). |
| `--allow-on-warning` | Non-interactively allow commands with only warning-level findings, instead of prompting. |
| `--block-on-warning` | Non-interactively block commands with only warning-level findings, instead of prompting. |

The `SCFW_ON_WARNING` environment variable (`allow` or `block`) has the same effect as `--allow-on-warning`/`--block-on-warning` and takes precedence over them when set, which is useful for enforcing a consistent policy across a CI environment without changing every invocation. In a non-interactive context (no attached terminal), a warning-level result is blocked by default unless one of these mechanisms is used, so a warning can never be silently ignored.

### Experimental package registry proxy

To evaluate package downloads made by npm, Yarn, pnpm, Bun, pip, Poetry, or uv,
run the package manager through the experimental proxy mode. Twine is not a
supported proxy manager. Commands unknown to SCFW still receive the same
process-local registry overrides, and requests they send to a configured
package index are forwarded through the proxy:

```bash
$ scfw proxy -- npm install react
scfw proxy: POST /evaluate
scfw proxy: POST /report outcome=ALLOW
```

For example, Python installation commands use the same interface:

```bash
$ scfw proxy -- pip install requests
$ scfw proxy -- poetry install
$ scfw proxy -- uv sync
```

To test npm's behavior for a registry failure without contacting the registry,
return a chosen status for every intercepted request:

```bash
$ scfw proxy --http-status 503 -- npm install react
```

`--http-status` accepts final HTTP response codes from 200 through 599. Synthetic
responses have empty bodies.

Proxy mode does not classify package-manager commands. It applies process-local
registry overrides to every invocation and forwards every registry request. The
npm and PyPI ecosystem handlers recognize distribution-download GET requests
and evaluate the identified package before contacting the artifact host. Other
requests—including metadata, authentication, writes, and unknown registry
routes—are forwarded without policy evaluation. Install and sync operations use
the manager's immutable/frozen-lockfile mode (or Yarn Classic's pure-lockfile
mode) so an ephemeral loopback URL is not persisted by those operations. Registry,
index, and config-file overrides on the wrapped command line are rejected; put
those values in the manager's normal configuration so SCFW can discover and
route every configured registry.

This reverse-proxy experiment overrides package-download indexes, not every
possible service endpoint a package manager may use. A separately configured
publish repository may therefore be contacted directly. Dependency-mutating
commands such as `add`, `update`, or `lock` are proxied, but can persist an
ephemeral proxy URL if they rewrite a lockfile; use the immutable install/sync
workflows when testing policy evaluation.

The npm adapter requires npm 8 or later. Registry, npmrc-location, prefix, and
authentication configuration must be supplied through npmrc files or environment
variables rather than npm command-line options. Effective global and project
configuration locations are rejected explicitly because proxy mode cannot safely
isolate writes to those files without changing npm's command semantics.

Each package-manager adapter reads its effective default and named/scoped index
configuration. SCFW then starts a reverse proxy on an ephemeral loopback port
and applies local registry URLs only to the spawned process. Registry requests,
responses, URLs, and bodies are not logged. Standard output records only when
SCFW sends an evaluation or final outcome report; package coordinates are omitted
from those events. Registry and package download URLs in npm packuments, Python
simple-index HTML, and PEP 691 JSON responses are routed back through the proxy
so subsequent downloads are
observed as well. Ephemeral proxy URLs are omitted from generated npm lockfiles.
When a distribution download is requested, the npm or PyPI handler derives its
package name and version and evaluates that package with the configured Datadog
policy. Non-allow decisions and evaluation failures return HTTP 403 without
contacting the artifact host. Repeated concurrent downloads of the same package
share one evaluation.

Proxy mode does not edit global, user, or project package-manager configuration
files. npm uses an inherited protected descriptor, Bun and Poetry use temporary
configuration/bootstrap files, and the remaining managers use child-process
arguments or environment variables. Consequently the original configuration
survives normal completion, interruption, or an abrupt SCFW exit.

Private registries are supported through npmrc/Yarn/Bun credentials, URL or
netrc credentials for Python managers, and uv's credentials store. Unsafe TLS
exceptions and keyring modes that cannot be scoped safely through the proxy are
rejected with an explanatory error; configure a trusted CA bundle instead.

## Datadog Code Security integration

[Datadog Code Security](https://www.datadoghq.com/product/code-security/) integrates with Supply Chain Firewall to provide a way of defining custom `ALLOW` or `BLOCK` policies that apply to all of your SCFW deployment from within the Datadog app. The outcomes of completed runs of the `scfw` CLI are also reported into Code Security, providing valuable observability into how package managers and third-party code are used across your fleet. Datadog only sees package metadata (ecosystem, name, version, artifact source) and the commands being run: no package source code is ever reported to Datadog by Supply Chain Firewall.

## Development

We welcome contributions to Supply Chain Firewall.  Refer to the [CONTRIBUTING](https://github.com/DataDog/supply-chain-firewall/blob/v4/CONTRIBUTING.md) guide for instructions on setting up for development.

## Authors

* [Ian Kretz](https://github.com/ikretz)
* [Tesnim Hamdouni](https://github.com/tesnim5hamdouni)
* [Sebastian Obregoso](https://www.linkedin.com/in/sebastianobregoso/)

## Maintainers

* [Marc Wieser](https://github.com/marcwieserdev)
* [Daniel Strong](https://github.com/dastrong)
* [Ian Kretz](https://github.com/ikretz)
