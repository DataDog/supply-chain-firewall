# Supply-chain firewall

This supply-chain firewall is a command-line tool for preventing the installation of vulnerable or malicious PyPI and npm packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

The firewall collects all targets that would be installed by a given `pip` or `npm` command and checks them against reputable sources of data on open source malware and vulnerabilities.  The installation is blocked when any target has been flagged by any data source.

Current data sources used are:

- Datadog Security Research's public malicious packages [dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [OSV.dev](https://osv.dev) disclosures

## Installation

Clone the repository and run the following commands.  This will install the `scfw` command-line program into your global Python environment.

```bash
$ cd path/to/repo/directory
$ pip install .
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

## Testing

To run the test suite, first install `scfw` and the development dependencies.  It is recommended to create a fresh virtual environment for testing:

```bash
$ python -m venv venv
$ . venv/bin/activate
(venv) $ pip install .
(venv) $ pip install -r requirements-dev.txt
```

You can now simply run the `pytest` command to run the test suite.

To facilitate testing "in the wild", `scfw` provides a `--dry-run` option that will verify any installation targets and exit without executing the given install command:

```bash
$ scfw --dry-run npm install axios
Exiting without installing, no issues found for installation targets.
```

Of course, one can always test inside a container or VM for an added layer of protection, if desired.

## Code quality

After setting up for local testing, the code can also be typechecked with `mypy` and linted with `flake8` by running the following commands in the top-level directory:

```bash
(venv) $ mypy --install-types --non-interactive scfw
```
```bash
(venv) $ flake8 scfw --count --show-source --statistics --max-line-length=120
```

## Feedback

All constructive feedback is welcome and greatly appreciated.  Please feel free to open an issue in this repository or reach out to Ian Kretz (ian.kretz@datadoghq.com) directly via Slack or email.
