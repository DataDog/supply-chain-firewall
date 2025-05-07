# Supply-Chain Firewall

![Test](https://github.com/DataDog/supply-chain-firewall/actions/workflows/test.yaml/badge.svg)
![Code quality](https://github.com/DataDog/supply-chain-firewall/actions/workflows/code_quality.yaml/badge.svg)

<p align="center">
  <img src="https://github.com/DataDog/supply-chain-firewall/blob/main/images/logo.png?raw=true" alt="Supply-Chain Firewall" width="300" />
</p>

Supply-Chain Firewall is a command-line tool for preventing the installation of malicious PyPI and npm packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

![scfw demo usage](https://github.com/DataDog/supply-chain-firewall/blob/main/images/demo.gif?raw=true)

Given a command for a supported package manager, Supply-Chain Firewall collects all targets that would be installed by the command and checks them against reputable sources of data on open source malware and vulnerabilities.  The command is automatically blocked from running when any data source finds that any target is malicious.  In cases where a data source reports other findings for a target, they are presented to the user along with a prompt confirming intent to proceed with the installation.

Default data sources include:

- Datadog Security Research's public [malicious packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [OSV.dev](https://osv.dev) advisories

Users may also implement verifiers for alternative data sources. A template for implementating custom verifiers may be found in `examples/verifier.py`. Details may also be found in the API documentation.

The principal goal of Supply-Chain Firewall is to block 100% of installations of known-malicious packages within the purview of its data sources.

## Getting started

### Installation

The recommended way to install Supply-Chain Firewall is via [`pipx`](https://pipx.pypa.io/):

```bash
$ pipx install scfw
```

This will install the `scfw` command-line program into an isolated Python environment on your system and make it available in any other Python environment, including ephemeral ones created with `venv` or `virtualenv`.  `pipx` may be installed via Homebrew on macOS or via the system package manager on major Linux distributions.  Be sure to run `pipx ensurepath` after installation to properly configure your `PATH`.

Supply-Chain Firewall can also be installed via `pip install scfw` directly into the active Python environment.

To check whether the installation succeeded, run the following command and verify that you see output similar to the following.

```bash
$ scfw --version
2.0.0
```

### Post-installation steps

To get the most out of Supply-Chain Firewall, it is recommended to run the `scfw configure` command after installation.  This script will walk you through configuring your environment so that all commands for supported package managers are passively run through `scfw` as well as enabling Datadog logging, described in more detail below.

```bash
$ scfw configure
...
```

### Compatibility and limitations

|  Package manager  |  Compatible versions  |        Inspected subcommands       |
| :---------------: | :-------------------: | :--------------------------------: |
| npm               | >= 7.0                | `install` (including aliases)      |
| pip               | >= 22.2               | `install`                          |
| poetry            | >= 1.7                | `add`, `install`, `sync`, `update` |

In keeping with its goal of blocking 100% of known-malicious package installations, `scfw` will refuse to run with an incompatible version of a supported package manager.  Please upgrade to or verify that you are running a compatible version before using this tool.

Supply-Chain Firewall may only know how to inspect some of the "installish" subcommands for its supported package managers.  These are shown in the above table.  Any other subcommands are always allowed to run.

Currently, Supply-Chain Firewall is only fully supported on macOS systems, though it should run as intended on common Linux distributions.  It is currently not supported on Windows.

### Uninstalling Supply-Chain Firewall

Supply-Chain Firewall may be uninstalled via `pip(x) uninstall scfw`.  Before doing so, be sure to run the command `scfw configure --remove` to remove any Supply-Chain Firewall-managed configuration you may have previously added to your environment.

```bash
$ scfw configure --remove
...
```

## Usage

To use Supply-Chain Firewall, simply prepend `scfw run` to the command you want to run.

```
$ scfw run npm install react
$ scfw run pip install -r requirements.txt
$ scfw run poetry add git+https://github.com/DataDog/guarddog
```

For `pip install` commands, packages will be installed in the same environment (virtual or global) in which the command was run.

## Datadog Log Management integration

Supply-Chain Firewall can optionally send logs of blocked and successful installations to Datadog.

![scfw datadog log](https://github.com/DataDog/supply-chain-firewall/blob/main/images/datadog_log.png?raw=true)

Users can configure their environments so that Supply-Chain Firewall forwards logs either via the Datadog HTTP API (requires an API key) or to a local Datadog Agent process.  Configuration consists of setting necessary environment variables and, for Agent log forwarding, configuring the Datadog Agent to accept logs from Supply-Chain Firewall.

To opt in, use the `scfw configure` command to interactively or non-interactively configure your environment for Datadog logging.

Supply-Chain Firewall can integrate with user-supplied loggers.  A template for implementating a custom logger may be found in `examples/logger.py`. Refer to the API documentation for details.

## Development

We welcome community contributions to Supply-Chain Firewall.  Refer to the [CONTRIBUTING](https://github.com/DataDog/supply-chain-firewall/blob/main/CONTRIBUTING.md) guide for instructions on building the API documentation and setting up for development.

## Maintainers

- [Ian Kretz](https://github.com/ikretz)
- [Sebastian Obregoso](https://www.linkedin.com/in/sebastianobregoso/)
