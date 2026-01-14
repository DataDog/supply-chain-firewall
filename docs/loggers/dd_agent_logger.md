# Datadog Agent logger

The Datadog Agent logger submits JSON logs of successful `run` and `audit` actions taken by Supply-Chain Firewall to a properly configured local Datadog Agent process over ad hoc TCP connections.

![scfw datadog log](https://github.com/DataDog/supply-chain-firewall/blob/main/docs/images/datadog_log.png?raw=true)

Note that the Datadog Agent must already be separately [configured](https://docs.datadoghq.com/agent/logs/#activate-log-collection) for log collection in order to use this logger.

Users may configure the behavior of this logger via the following environment variables:

* `SCFW_DD_AGENT_LOG_PORT`:
    Takes a TCP port number on which the local Datadog Agent has been configured to receive logs from Supply-Chain Firewall.  Required to enable this logger.

    The `scfw configure` [subcommand](https://github.com/DataDog/supply-chain-firewall/blob/main/docs/subcommands/configure.md) should be used in order to simultaneously configure the Datadog Agent to receive SCFW logs and write this environment variable into the user's `~/.bashrc` and `~/.zshrc` files.

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
