# Local file logger

The local file logger writes JSON Lines logs of all `run` and `audit` actions taken by Supply-Chain Firewall to a specified local log file.  Users are strongly encouraged to enable this logger, as having a centralized record of executed package manager commands, their outcomes, and installed packages over time can be useful in incident response scenarios.

```json
{"source": "scfw", "service": "scfw", "version": "2.5.0", "env": "dev", "hostname": "bitshq", "username": "bits", "package_manager": "poetry", "executable": "~/.local/bin/poetry", "ecosystem": "PyPI", "msg": "Command 'poetry add git+https://github.com/tree-sitter/py-tree-sitter' was allowed", "action": "ALLOW", "created": 1768396428.952134, "targets": ["tree-sitter-0.25.2"], "verified": true, "warned": false}
{"source": "scfw", "service": "scfw", "version": "2.5.0", "env": "dev", "hostname": "bitshq", "username": "bits", "created": 1768406580.338711, "msg": "Command 'pip install suspicious-package' was blocked", "verified": true, "targets": ["suspicious-package-0.0.0"], "action": "BLOCK", "ecosystem": "PyPI", "warned": true, "executable": "~/supply-chain-firewall/venv/bin/python3", "package_manager": "pip"}
```

Users may configure the behavior of this logger via the following environment variables:

* `SCFW_LOG_FILE`:
    Takes a local filesystem path to the file where SCFW should write JSON Lines log entries.

* `SCFW_HOME`:
    Takes a local filesystem path to the SCFW home directory.

    By default, JSON Lines log entries are written to `$SCFW_HOME/scfw.log` if `SCFW_LOG_FILE` is not set.  If neither is set, the logger is disabled.
