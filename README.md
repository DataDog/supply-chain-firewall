# Supply-Chain Firewall

![Test](https://github.com/DataDog/supply-chain-firewall/actions/workflows/test.yaml/badge.svg)
![Code quality](https://github.com/DataDog/supply-chain-firewall/actions/workflows/code_quality.yaml/badge.svg)

The supply-chain firewall is a command-line tool for preventing the installation of malicious PyPI and npm packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

![scfw demo usage](images/demo.png)

The firewall collects all targets that would be installed by a given `pip` or `npm` command and checks them against reputable sources of data on open source malware and vulnerabilities.  The command is automatically blocked when any data source finds that any target is malicious.  In cases where a data source reports other findings for a target, the findings are presented to the user along with a prompt confirming intent to proceed with the installation.

Default data sources include:

- Datadog Security Research's public malicious packages [dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [OSV.dev](https://osv.dev) disclosures

Users may also implement verifiers for alternative data sources. A template for implementating custom verifiers may be found in `examples/verifier.py`. Details may also be found in the API documentation.

The principal goal of the supply-chain firewall is to block 100% of installations of known-malicious packages within the purview of its data sources.

## Getting started

### Installation

Clone the repository and run `make install`.  This will install the `scfw` command-line program into your global Python environment.  If desired, this can be done inside a `virtualenv`.

```bash
git clone https://github.com/DataDog/supply-chain-firewall.git
cd supply-chain-firewall
make install
```

To check whether the installation succeeded, run the following command and verify that you see output similar to the following.
```bash
$ scfw --version
1.0.0
```

### Post-installation steps

To get the most out of the supply-chain firewall, it is recommended to run the `scfw configure` command after installation.  This script will walk you through configuring your environment so that all `pip` or `npm` commands are passively run through the firewall as well as enabling Datadog logging, described in more detail below.

```bash
$ scfw configure
...
```

### Compatibility

The supply-chain firewall is compatible with `pip >= 22.2` and `npm >= 7.0`.  In keeping with its goal of blocking 100% of known-malicious package installations, the firewall will refuse to run with an incompatible version of `pip` or `npm`.  Please upgrade to or verify that you are running a compatible version of `pip` or `npm` before using this tool.

Currently, the supply-chain firewall is only fully supported on macOS systems, though it should run as intended on most common Linux distributions.  It is currently not supported on Windows.

## Usage

To use the supply-chain firewall, just prepend `scfw run` to the `pip install` or `npm install` command you want to run.

```
$ scfw run npm install react
$ scfw run pip install -r requirements.txt
```

For `pip install` commands, the firewall will install packages in the same environment (virtual or global) in which the command was run.

## Limitations

Unlike `pip`, a variety of `npm` operations beyond `npm install` can end up installing new packages.  For now, only `npm install` commands are in scope for analysis with the supply-chain firewall.  We are hoping to extend the firewall's purview to other "installish" `npm` commands over time.

## Datadog Logs integration

The supply-chain firewall can optionally send logs of blocked and successful installations to Datadog.

![scfw datadog log](images/datadog_log.png)

To opt in, set the environment variable `DD_API_KEY` to your Datadog API key, either directly in your shell environment or in a `.env` file in the current working directory.  A logging level may also be selected by setting the environment variable `SCFW_DD_LOG_LEVEL` to one of `ALLOW`, `ABORT` or `BLOCK`.  The `BLOCK` level only logs blocked installations, `ABORT` logs blocked and aborted installations, and `ALLOW` logs these as well as successful installations.  The `BLOCK` level is set by default, i.e., when `SCFW_DD_LOG_LEVEL` is either not set or does not contain a valid log level.

You can also use the `scfw configure` command to walk through the steps of configuring your environment for Datadog logging.

The firewall can integrate with user-supplied loggers.  A template for implementating a custom logger may be found in `examples/logger.py`. Refer to the API documentation for details.

## Development

We welcome community contributions to the supply-chain firewall.  Refer to the [CONTRIBUTING](./CONTRIBUTING.md) guide for instructions on building the API documentation and setting up for development.

## Maintainers

- [Ian Kretz](https://github.com/ikretz)
- [Sebastian Obregoso](https://www.linkedin.com/in/sebastianobregoso/)
