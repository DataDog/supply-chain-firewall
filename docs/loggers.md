# Supply-Chain Firewall default loggers

## Datadog Agent logger

The Datadog Agent logger submits JSON logs of successful `run` and `audit` actions taken by Supply-Chain Firewall to a properly configured local Datadog Agent process over ad hoc TCP connections.

Note that the Datadog Agent must already be separately [configured](https://docs.datadoghq.com/agent/logs/#activate-log-collection) for log collection in order to use this logger.

Users may configure the behavior of this logger via the following environment variables:

* `SCFW_DD_AGENT_LOG_PORT`:
    Takes a TCP port number on which the local Datadog Agent has been configured to receive logs from Supply-Chain Firewall.  Required to enable this logger.

    The `scfw configure` [subcommand](https://github.com/DataDog/supply-chain-firewall/blob/main/docs/subcommands.md#scfw-configure) should be used in order to simultaneously configure the Datadog Agent to receive SCFW logs and write this environment variable into the user's `~/.bashrc` and `~/.zshrc` files.

* `DD_ENV`:
    Takes a string identifying the environment where Supply-Chain Firewall is running.  Defaults to `dev` if not set.

* `DD_LOG_LEVEL`:
    Takes one of the strings `ALLOW` or `BLOCK`.

    This value controls which `run` actions are forwarded to Datadog as follows:
    - `ALLOW`: Logs of all `run` actions are forwarded to Datadog
    - `BLOCK`: Logs of only blocking `run` actions are forwarded to Datadog

    In all cases, `audit` actions are forwarded to Datadog.

* `SCFW_DD_LOG_ATTRIBUTES`:
    Takes a single JSON object containing custom log attributes that should be included in the log forwarded to Datadog.

    ```
    SCFW_DD_LOG_ATTRIBUTES='{"mascot_name": "Bits", "location": "New York"}'
    ```

* `SCFW_DD_LOG_ATTRIBUTES_FILE`:
    Takes a local filesystem path to a JSON file containing custom log attributes.

    Attributes read from `SCFW_DD_LOG_ATTRIBUTES` take precendence over those read from file in case of overlap.

* `SCFW_HOME`:
    Takes the local filesystem path of the SCFW home directory.

    If `SCFW_DD_LOG_ATTRIBUTES_FILE` is not set, this logger will look for custom log attributes at `$SCFW_HOME/dd_logger/log_attributes.json` by default, with `SCFW_DD_LOG_ATTRIBUTES` again taking precedence over attributes read from file.

## Datadog API logger

The Datadog API logger submits JSON logs of successful `run` and `audit` actions taken by Supply-Chain Firewall to the Datadog HTTP API.

Users may configure the behavior of this logger via the following environment variables:

* `DD_API_KEY`:
    Takes a Datadog API key.  Required to enable this logger.

    The `scfw configure` [subcommand](https://github.com/DataDog/supply-chain-firewall/blob/main/docs/subcommands.md#scfw-configure) can be used to write this environment variable into the user's `~/.bashrc` and `~/.zshrc` files.

* `DD_SITE`:
    Takes a [Datadog site parameter](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site) for setting the region where the target Datadog organization is hosted.  Defaults to `US1` if not set.

* `DD_ENV`:
    Takes a string identifying the environment where Supply-Chain Firewall is running.  Defaults to `dev` if not set.

* `DD_LOG_LEVEL`:
    Takes one of the strings `ALLOW` or `BLOCK`.

    This value controls which `run` actions are forwarded to Datadog as follows:
    - `ALLOW`: Logs of all `run` actions are forwarded to Datadog
    - `BLOCK`: Logs of only blocking `run` actions are forwarded to Datadog

    In all cases, `audit` actions are forwarded to Datadog.

* `SCFW_DD_LOG_ATTRIBUTES`:
    Takes a single JSON object containing custom log attributes that should be included in the log forwarded to Datadog.

    ```
    SCFW_DD_LOG_ATTRIBUTES='{"mascot_name": "Bits", "location": "New York"}'
    ```

* `SCFW_DD_LOG_ATTRIBUTES_FILE`:
    Takes a local filesystem path to a JSON file containing custom log attributes.

    Attributes read from `SCFW_DD_LOG_ATTRIBUTES` take precendence over those read from file in case of overlap.

* `SCFW_HOME`:
    Takes the local filesystem path of the SCFW home directory.

    If `SCFW_DD_LOG_ATTRIBUTES_FILE` is not set, this logger will look for custom log attributes at `$SCFW_HOME/dd_logger/log_attributes.json` by default, with `SCFW_DD_LOG_ATTRIBUTES` again taking precedence over attributes read from file.

## Local file logger

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
