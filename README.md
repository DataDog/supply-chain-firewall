# Supply Chain Firewall

![Build](https://github.com/DataDog/supply-chain-firewall/actions/workflows/build.yml/badge.svg)
![Test](https://github.com/DataDog/supply-chain-firewall/actions/workflows/test.yml/badge.svg)
![Code quality](https://github.com/DataDog/supply-chain-firewall/actions/workflows/code-quality.yml/badge.svg)

<p align="center">
  <img src="https://github.com/DataDog/supply-chain-firewall/blob/v4/images/logo.png?raw=true" alt="Supply Chain Firewall" width="300" />
</p>

Supply Chain Firewall (SCFW) is a command-line tool for preventing the installation of malicious npm and PyPI packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

Given a command for a supported package manager, Supply Chain Firewall collects all package targets that would be installed by the command and evaluates them against Datadog Security Research's threat intelligence feed on known-malicious and compromised open source packages. It also applies custom policy rules configured within your Datadog organization under the [Datadog Code Security](https://www.datadoghq.com/product/code-security/) integration with Supply Chain Firewall. The command is allowed or blocked from running on the basis of this policy evaluation. In cases where only warning-level findings are indicated, they are presented to the user along with a prompt confirming intent to proceed with the command.

---
### Interested in SCFW for your business use-case? [Enroll](https://docs.google.com/forms/d/1Xqh5h1n3-jC7au2t30fdTq732dkTJqt_cb7C7T-AkPc/edit) as a design partner.
---

## Getting started

### Installation

Supply Chain Firewall is distributed as a single Go binary with no runtime dependencies. The recommended way to install it is via `go install` (requires Go 1.26+):

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
    --alias-pip \
    --alias-poetry
```

When passing these values via shell variables, e.g. in scripts, prefer this `=` form: `--dd-api-key=$DD_API_KEY --dd-app-key=$DD_APP_KEY --dd-site=$DD_SITE`.

This does two things:

1. Stores your Datadog API key and application key securely in your system's keychain, so credentials don't need to be kept in plaintext or supplied on every command.
2. Enables `scfw` shell completion (from `.zshrc` for zsh) and adds shell wrappers to your `.bashrc`, `.bash_profile`, `.zshrc`, and `.zprofile` (whichever already exist) so that `npm`, `pip`/`pip3`, and/or `poetry` transparently run through `scfw`. The wrappers preserve each package manager's existing completion integration. Restart your shell (or source the relevant rc file) for the changes to take effect.

`scfw configure` is idempotent and may be re-run at any time to change your configuration. It manages its own clearly indicated block of your shell rc files and never touches anything else you've added.

Bash completion requires the [`bash-completion`](https://github.com/scop/bash-completion) package to be installed and initialized before the SCFW managed block is sourced. SCFW reports a warning at interactive shell startup and leaves completion disabled when that dependency is unavailable. Non-interactive shells skip completion setup.

Available `configure` options:

| Flag | Description |
| --- | --- |
| `--dd-api-key` | Datadog API key used for policy evaluation and reporting. |
| `--dd-app-key` | Datadog application key used for policy evaluation and reporting. |
| `--dd-site` | Datadog site parameter used for policy evaluation and reporting (default: `datadoghq.com`). |
| `--alias-npm` | Add a shell wrapper to run all npm commands through `scfw`. |
| `--alias-pip` | Add shell wrappers to run all pip/pip3 commands through `scfw`. |
| `--alias-poetry` | Add a shell wrapper to run all poetry commands through `scfw`. |
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

Note that, once shell wrappers have been configured via `scfw configure --alias-npm`/`--alias-pip`/`--alias-poetry`, the explicit `scfw run --` prefix is no longer needed: commands for these package managers run through `scfw` automatically.

`scfw run` supports the following options:

| Flag | Description |
| --- | --- |
| `--executable` | Package manager executable to use for running commands (default: environmentally determined). |
| `--error-on-block` | Treat blocked commands as errors, i.e. exit non-zero (useful for scripting and CI). |
| `--allow-on-warning` | Non-interactively allow commands with only warning-level findings, instead of prompting. |
| `--block-on-warning` | Non-interactively block commands with only warning-level findings, instead of prompting. |

The `SCFW_ON_WARNING` environment variable (`allow` or `block`) has the same effect as `--allow-on-warning`/`--block-on-warning` and takes precedence over them when set, which is useful for enforcing a consistent policy across a CI environment without changing every invocation. In a non-interactive context (no attached terminal), a warning-level result is blocked by default unless one of these mechanisms is used, so a warning can never be silently ignored.

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
