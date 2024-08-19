# Supply-chain firewall

This supply-chain firewall is a command-line tool for preventing the installation of vulnerable or malicious PyPI and npm packages.  It is intended primarily for use by engineers to protect their development workstations from compromise in a supply-chain attack.

## Installation

Clone the repository and run the following commands.  This can be done in a `virtualenv` if preferred.

```bash
$ cd path/to/repo/directory
$ pip install .
```

The `scfw` command-line program should then be available.

## Usage

To use the supply-chain firewall, just prepend `scfw` to the `pip install` or `npm install` command you want to run.

```bash
$ scfw npm install react
$ scfw pip install -r requirements.txt
```

## Sample blocked installation output

```bash
$ scfw npm install basementio
Installation target basementio@0.0.1-security:
  - Package basementio has been determined to be malicious by Datadog Security Research
  - An OSV.dev disclosure for package basementio exists (OSVID: MAL-2024-7874)

The installation request was blocked.  No changes have been made.
```

## Current limitations

Only commands that begin with `pip install` or `npm install` are currently allowed.  We plan to support a more diverse range of commands over time.

## Feedback

All constructive feedback is welcome and greatly appreciated.  Please feel free to open an issue in this repository or reach out to Ian Kretz (ian.kretz@datadoghq.com) directly via Slack or email.
