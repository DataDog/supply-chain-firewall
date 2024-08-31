# Supply-chain firewall

This supply-chain firewall is a command-line tool for preventing the installation of vulnerable or malicious PyPI and npm packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

The firewall collects all targets that would be installed by a given `pip` or `npm` command and checks them against reputable sources of data on open source malware and vulnerabilities.  The installation is blocked when any target has been flagged by any data source.

Current data sources used are:

- Datadog Security Research's public malicious packages [dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [OSV.dev](https://osv.dev) disclosures

## Compatibility

The supply-chain firewall is compatible with `pip >= 22.2` and generally compatible with recent versions of `npm >= 10.x`.

In order to verify whether your `npm` is compatible, run an `npm install --dry-run` command for any package you do not already have installed and verify that the output resembles the following:

```
$ npm install --dry-run react
add js-tokens 4.0.0
add loose-envify 1.4.0
add react 18.3.1

added 3 packages in 127ms
```

We hope to add support for older `npm` versions in the near future.

Be advised that the firewall may fail to block installations of vulnerable or malicious packages if used with incompatible versions of `pip` or `npm`.

## Installation

Clone the repository, `cd` into the downloaded directory and run `make install`.  This will install the `scfw` command-line program into your global Python environment.  This can also be done inside a `virtualenv`, if desired.

```
$ scfw
usage: scfw [options] COMMAND

A tool to prevent the installation of vulnerable or malicious pip and npm packages

options:
  -h, --help         show this help message and exit
  --dry-run          Skip installation step regardless of verification results
  --log-level LEVEL  Desired logging level (default: WARNING, options: DEBUG, INFO, WARNING, ERROR)
  --executable PATH  Python or npm executable to use for running commands (default: environmentally determined)
```

## Usage

To use the supply-chain firewall, just prepend `scfw` to the `pip install` or `npm install` command you want to run.

```bash
$ scfw npm install react
$ scfw pip install -r requirements.txt
```

For `pip install` commands, the firewall will install packages in the same environment (virtual or global) in which the command was run.

If desired, the following aliases can be added to one's `.bashrc`/`.zshrc` file to passively run all `pip` and `npm` commands through the firewall.

```
alias pip="scfw pip"
alias npm="scfw npm"
```

## Sample blocked installation output

```bash
$ scfw npm install basementio
Installation target basementio@0.0.1-security:
  - Package basementio has been determined to be malicious by Datadog Security Research
  - An OSV.dev disclosure for package basementio exists (OSVID: MAL-2024-7874)

The installation request was blocked.  No changes have been made.
```

## Testing and development

To set up for testing and development, create a fresh `virtualenv`, activate it and run `make install-dev`.  This will install `scfw` and the development dependencies.

### Testing

The test suite may be executed in the development environment by running `make test`.  To additionally view code coverage, run `make coverage`.

To facilitate testing "in the wild", `scfw` provides a `--dry-run` option that will verify any installation targets and exit without executing the given install command:

```bash
$ scfw --dry-run npm install axios
Exiting without installing, no issues found for installation targets.
```

Of course, one can always test inside a container or VM for an added layer of protection, if desired.

### Code quality

The supply-chain firewall code may be typechecked with `mypy` and linted with `flake8`.  Run `make typecheck` or `make lint`, respectively, in the environment where the development dependencies have been installed.

Run `make checks` to run the full suite of code quality checks, including tests.  These are the same checks that run in the firewall repository's CI, albeit with the tests run against various `pip` and `npm` versions to ensure compatibility.

### Documentation

API documentation may be built via `pydoc` by running `make docs` from your development environment.  This will automatically open the documentation in your system's default browser.

## Feedback

All constructive feedback is welcome and greatly appreciated.  Please feel free to open an issue in this repository or reach out to Ian Kretz (ian.kretz@datadoghq.com) directly via Slack or email.
