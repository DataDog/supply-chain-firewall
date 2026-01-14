# Custom findings list verifier

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
