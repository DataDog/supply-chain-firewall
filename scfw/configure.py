"""
Implements the supply-chain firewall's `configure` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scfw.logger import FirewallAction

_log = logging.getLogger(__name__)

DD_SOURCE = "scfw"
"""
Source value for Datadog logging.
"""

DD_SERVICE = "scfw"
"""
Service value for Datadog logging.
"""

DD_ENV = "dev"
"""
Default environment value for Datadog logging.
"""

DD_API_KEY_VAR = "DD_API_KEY"
"""
The environment variable under which the firewall looks for a Datadog API key.
"""

DD_LOG_LEVEL_VAR = "SCFW_DD_LOG_LEVEL"
"""
The environment variable under which the firewall looks for a Datadog log level setting.
"""

DD_AGENT_PORT_VAR = "SCFW_DD_AGENT_LOG_PORT"
"""
The environment variable under which the firewall looks for a port number on which to
forward firewall logs to the local Datadog Agent.
"""

_DD_AGENT_DEFAULT_LOG_PORT = "10365"

_CONFIG_FILES = [".bashrc", ".zshrc"]

_BLOCK_START = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_END = "# END SCFW MANAGED BLOCK"

_GREETING = (
    "Thank you for using scfw, the Supply-Chain Firewall by Datadog!\n\n"
    "scfw is a tool for preventing the installation of malicious PyPI and npm packages.\n\n"
    "This script will walk you through setting up your environment to get the most out\n"
    "of scfw. You can rerun this script at any time.\n"
)


def run_configure(args: Namespace) -> int:
    """
    Configure the environment for use with the supply-chain firewall.

    Args:
        args: A `Namespace` containing the parsed `configure` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    try:
        # The CLI parser guarantees that all optional arguments are present
        interactive = not any(
            {args.alias_pip, args.alias_npm, args.dd_agent_port, args.dd_api_key, args.dd_log_level}
        )

        if interactive:
            print(_GREETING)
            config = _get_config_interactive()
        else:
            config = vars(args)

        if not config:
            return 0

        if (port := config["dd_agent_port"]):
            _configure_agent_logging(port)

        update_config_files(config)

        if interactive:
            print(_get_farewell(config))

        return 0

    except Exception as e:
        _log.error(e)
        return 1


def update_config_files(config: dict) -> None:
    """
    Update Supply-Chain Firewall's configuration in all supported files.

    Args:
        config: A `dict` of configuration options to format and write to file.
    """
    def enclose(config_str: str) -> str:
        return f"{_BLOCK_START}{config_str}\n{_BLOCK_END}"

    def format_config(config: dict) -> str:
        config_str = ''

        if config["alias_pip"]:
            config_str += '\nalias pip="scfw run pip"'
        if config["alias_npm"]:
            config_str += '\nalias npm="scfw run npm"'
        if config["dd_agent_port"]:
            config_str += f'\nexport {DD_AGENT_PORT_VAR}="{config["dd_agent_port"]}"'
        if config["dd_api_key"]:
            config_str += f'\nexport {DD_API_KEY_VAR}="{config["dd_api_key"]}"'
        if config["dd_log_level"]:
            config_str += f'\nexport {DD_LOG_LEVEL_VAR}="{config["dd_log_level"]}"'

        return config_str

    def update_config_file(config_file: Path, config: dict) -> None:
        config_str = format_config(config)

        with open(config_file) as f:
            contents = f.read()

        pattern = f"{_BLOCK_START}(.*?){_BLOCK_END}"
        if not config_str:
            pattern = f"\n{pattern}\n"

        updated = re.sub(pattern, enclose(config_str) if config_str else '', contents, flags=re.DOTALL)
        if updated == contents and config_str not in contents:
            updated = f"{contents}\n{enclose(config_str)}\n"

        temp_fd, temp_file = tempfile.mkstemp(text=True)
        temp_handle = os.fdopen(temp_fd, 'w')
        temp_handle.write(updated)
        temp_handle.close()

        os.rename(temp_file, config_file)

    for file in [Path.home() / file for file in _CONFIG_FILES]:
        if file.exists():
            update_config_file(file, config)


def _get_config_interactive() -> dict:
    """
    Get the user's selection of configuration options in interactive mode.

    Returns:
        A `dict` containing the user's selected configuration options.
    """
    has_dd_api_key = os.getenv(DD_API_KEY_VAR) is not None

    questions = [
        inquirer.Confirm(
            name="alias_pip",
            message="Would you like to set a shell alias to run all pip commands through the firewall?",
            default=True
        ),
        inquirer.Confirm(
            name="alias_npm",
            message="Would you like to set a shell alias to run all npm commands through the firewall?",
            default=True
        ),
        inquirer.Confirm(
            name="dd_agent_logging",
            message="If you have the Datadog Agent installed locally, would you like to forward firewall logs to it?",
            default=False
        ),
        inquirer.Text(
            name="dd_agent_port",
            message=f"Enter the local port where the Agent will receive logs (default: {_DD_AGENT_DEFAULT_LOG_PORT})",
            ignore=lambda config: not config["dd_agent_logging"]
        ),
        inquirer.Confirm(
            name="dd_api_logging",
            message="Would you like to enable sending firewall logs to Datadog using an API key?",
            default=False,
            ignore=lambda config: has_dd_api_key or config["dd_agent_logging"]
        ),
        inquirer.Text(
            name="dd_api_key",
            message="Enter a Datadog API key",
            validate=lambda _, current: current != '',
            ignore=lambda config: has_dd_api_key or not config["dd_api_logging"]
        ),
        inquirer.List(
            name="dd_log_level",
            message="Select the desired log level for Datadog logging",
            choices=[str(action) for action in FirewallAction],
            ignore=lambda config: not (config["dd_agent_logging"] or has_dd_api_key or config["dd_api_logging"])
        )
    ]

    config = inquirer.prompt(questions)

    # Patch for inquirer's broken `default` option
    if config["dd_agent_logging"] and not config["dd_agent_port"]:
        config["dd_agent_port"] = _DD_AGENT_DEFAULT_LOG_PORT

    return config


def _configure_agent_logging(port: str):
    """
    Configure a local Datadog Agent for accepting logs from the firewall.

    Args:
        port: The local port number where the firewall logs will be sent to the Agent.

    Raises:
        ValueError: An invalid port number was provided.
        RuntimeError: An error occurred while querying the Agent's status.
    """
    if not (0 < int(port) < 65536):
        raise ValueError("Invalid port number provided for Datadog Agent logging")

    config_file = (
        "logs:\n"
        "  - type: tcp\n"
        f"    port: {port}\n"
        f'    service: "{DD_SERVICE}"\n'
        f'    source: "{DD_SOURCE}"\n'
    )

    try:
        agent_status = subprocess.run(
            ["datadog-agent", "status", "--json"], check=True, text=True, capture_output=True
        )
        agent_config_dir = json.loads(agent_status.stdout).get("config", {}).get("confd_path", "")
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Unable to query Datadog Agent status: please ensure the Agent is running. "
            "Linux users may need sudo to run this command."
        )

    scfw_config_dir = Path(agent_config_dir) / "scfw.d"
    scfw_config_file = scfw_config_dir / "conf.yaml"

    if not scfw_config_dir.is_dir():
        scfw_config_dir.mkdir()
    with open(scfw_config_file, 'w') as f:
        f.write(config_file)


def _get_farewell(config: dict) -> str:
    """
    Generate a farewell message in interactive mode based on the configuration
    options selected by the user.

    Args:
        config: The dictionary of user-selected configuration options.

    Returns:
        A `str` farewell message to print in interactive mode.
    """
    farewell = (
        "The environment was successfully configured for Supply-Chain Firewall."
        "\n\nPost-configuration tasks:"
        "\n* Update your current shell environment by sourcing from your .bashrc/.zshrc file."
    )

    if config.get("dd_agent_logging"):
        farewell += "\n* Restart the Datadog Agent in order for it to accept firewall logs."

    farewell += "\n\nGood luck!"

    return farewell
