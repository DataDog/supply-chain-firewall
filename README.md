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

## Sample blocked installation output

```bash
$ scfw npm install basementio
Installation target basementio@0.0.1-security:
  - Package basementio has been determined to be malicious by Datadog Security Research
  - An OSV.dev disclosure for package basementio exists (OSVID: MAL-2024-7874)

The installation request was blocked.  No changes have been made.
```

## Current limitations

For npm, only commands that begin with `npm install` are currently allowed.  We plan to support a more diverse range of commands over time.

## Testing

To facilitate testing against known-good packages, `scfw` has a `--dry-run` option that will verify installation targets and exit without executing the given install command:

```bash
$ scfw --dry-run npm install axios
Exiting without installing, no issues found for installation targets.
```

As for testing against known-malicious targets, any of the packages listed in Datadog's public malicious software packages [dataset](https://github.com/DataDog/malicious-software-packages-dataset) should be reliably blocked.  As for additional precautions, one can always use the `--dry-run` flag or test inside a container or VM, if desired.


## Feedback

All constructive feedback is welcome and greatly appreciated.  Please feel free to open an issue in this repository or reach out to Ian Kretz (ian.kretz@datadoghq.com) directly via Slack or email.
