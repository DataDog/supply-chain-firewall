# Supply-Chain Firewall default verifiers

## Package minimum age verifier

The minimum package age verifier checks whether a given package has a certain minimum age, defined to be the number of hours elapsed since the time of the package's creation on the ecosystem's package registry.  If a given package does not have the required minimum age, a single `WARNING`-level finding is returned.

```bash
scfw run pip install foo
Package foo-1.0.1:
  - Package foo was created less than 24 hours ago: treat new packages with caution
```

This verifier provides an additional level of protection to SCFW users against supply-chain attacks: all things being equal, recently-created packages are generally unvetted and should be treated with a greater deal of initial skepticism before being installed.

Users may configure the behavior of this verifier via the following environment variables:

* `SCFW_PACKAGE_MINIMUM_AGE`:
    Takes a positive integer number representing the desired minimum package age in hours.  A default value of 24 hours is used if this is not set.

## Datadog malicious packages verifier

The Datadog malicious packages verifier determines whether a given package is known to be malicious by checking for its inclusion in Datadog Security Research's public [malicious packages dataset](https://github.com/DataDog/malicious-software-packages-dataset).  In this case, it returns a single `CRITICAL` finding for the package.

```bash
$ scfw run npm install basementio
Package basementio@0.0.1-security:
  - Datadog Security Research has determined that package basementio@0.0.1-security is malicious
```

Users may configure the behavior of this verifier via the following environment variables:

* `SCFW_HOME`:
  Takes a local filesystem path to the SCFW home directory.

  Users are encouraged to configure `SCFW_HOME` in order to take advantage of local caching performed by this verifier.  Doing so eliminates per-package queries against the remote dataset and improves the performance of the verifier.

## Custom findings list verifier

The custom findings list verifier reads in user-provided lists of custom findings for specific packages and checks whether any given package has any findings in those lists.  It returns all findings pertaining to the given package present in all discoverable findings lists.

```bash
$ scfw run pip install pynamodb
Package pynamodb-6.1.0:
  - This package is licensed under an incompatible open source license and must not be used

The installation request was blocked. No changes have been made.
```

Findings lists are expressed in YAML.  A simple example of the expected format may be found [here](https://github.com/DataDog/supply-chain-firewall/blob/main/examples/findings_list.yaml).

Users may configure the behavior of this verifier via the following environment variables:

* `SCFW_HOME`:
    Takes the local filesystem path of the SCFW home directory.

    The findings list verifier looks for findings lists in the directory `$SCFW_HOME/list_verifier/`.  It is effectively disabled if `SCFW_HOME` is not set, if this directory under `SCFW_HOME` does not exist, or if there are no YAML files in this directory.

## OSV.dev advisories verifier

The [OSV.dev](https://osv.dev) advisories verifier queries the Open Source Vulnerabilities API for a given package to determine whether it has any associated security advisories.  One finding per returned advisory is returned by the verifier.  Malicious package (`MAL`) advisories result in `CRITICAL` findings, while any other advisories result in `WARNING` findings.

```bash
$ scfw run npm install basementio
Package basementio@0.0.1-security:
  - An OSV.dev malicious package advisory exists for package basementio@0.0.1-security:
      * https://osv.dev/vulnerability/MAL-2024-7874
```

Users may configure the behavior of this verifier via the following environment variables:

* `SCFW_OSV_VERIFIER_IGNORE`:
  Takes a local filesystem path to a text file containing a list of `WARNING`-level OSV advisory IDs that the verifier should ignore when analyzing the results returned from the OSV API.

  Ignore list files support entire advisory IDs as well as regular expressions.  For example, the following ignore list will cause the verifier to ignore a particular `GHSA` advisory and any `PYSEC` advisories:

  ```
  GHSA-4xh5-x5gv-qwph
  PYSEC.*
  ```

* `SCFW_HOME`:
  Takes the local filesystem path of the SCFW home directory.

  If `SCFW_OSV_VERIFIER_IGNORE` is not set, the verifier will instead look for an ignore list file at `$SCFW_HOME/osv_verifier/ignore.txt`
