# OSV.dev advisories verifier

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
