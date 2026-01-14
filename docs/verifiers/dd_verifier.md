# Datadog malicious packages verifier

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
