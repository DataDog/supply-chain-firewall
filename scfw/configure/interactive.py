"""
Provides utilities for interactively accepting configuration options from the user.
"""

import logging
from pathlib import Path
from typing import Optional

import inquirer  # type: ignore

from scfw.logger import FirewallAction

GREETING = (
    "Thank you for using scfw, the Supply-Chain Firewall by Datadog!\n\n"
    "Supply-Chain Firewall is a tool for preventing the installation of malicious npm and PyPI packages.\n\n"
    "This script will walk you through setting up your environment to get the most out of scfw.\n"
    "You can rerun this script at any time to update your configuration settings.\n"
)

_log = logging.getLogger(__name__)

_DD_AGENT_DEFAULT_LOG_PORT = "10365"


def get_answers() -> dict:
    """
    Get the user's selection of configuration options in interactive mode.

    Returns:
        A `dict` containing the user's selected configuration options.
    """
    home_dir_default = _get_home_dir_default()

    questions = [
        inquirer.Text(
            name="scfw_home",
            message=(
                "Enter a directory the firewall can use as a local cache"
                f" (default: {home_dir_default})" if home_dir_default else ""
            )
        ),
        inquirer.Confirm(
            name="alias_npm",
            message="Would you like to set a shell alias to run all npm commands through the firewall?",
            default=True
        ),
        inquirer.Confirm(
            name="alias_pip",
            message="Would you like to set a shell alias to run all pip commands through the firewall?",
            default=True
        ),
        inquirer.Confirm(
            name="alias_poetry",
            message="Would you like to set a shell alias to run all Poetry commands through the firewall?",
            default=True
        ),
        inquirer.Confirm(
            name="dd_agent_logger",
            message="If you have the Datadog Agent installed locally, would you like to forward firewall logs to it?",
            default=False
        ),
        inquirer.Text(
            name="dd_agent_port",
            message=f"Enter the local port where the Agent will receive logs (default: {_DD_AGENT_DEFAULT_LOG_PORT})",
            ignore=lambda answers: not answers["dd_agent_logger"]
        ),
        inquirer.Confirm(
            name="dd_api_logger",
            message="Would you like to forward firewall logs to the Datadog API? This requires an API key.",
            default=False,
            ignore=lambda answers: answers["dd_agent_logger"]
        ),
        inquirer.List(
            name="dd_log_level",
            message="Select the desired log level for Datadog logging",
            choices=[(_describe_log_level(action), str(action)) for action in FirewallAction],
            ignore=lambda answers: not (answers["dd_agent_logger"] or answers["dd_api_logger"])
        )
    ]

    answers = inquirer.prompt(questions)
    if answers is None:
        return {}

    # Patch for inquirer's strange `default` option
    if home_dir_default and not answers.get("scfw_home"):
        answers["scfw_home"] = home_dir_default

    # Patch for inquirer's broken `default` option
    if answers.get("dd_agent_logger") and not answers.get("dd_agent_port"):
        answers["dd_agent_port"] = _DD_AGENT_DEFAULT_LOG_PORT

    return answers


def get_farewell(answers: dict) -> str:
    """
    Generate a farewell message in interactive mode based on the configuration
    options selected by the user.

    Args:
        answers: The dictionary of user-selected configuration options.

    Returns:
        A `str` farewell message to print in interactive mode.
    """
    farewell = (
        "The environment was successfully configured for Supply-Chain Firewall."
        "\n\nPost-configuration tasks:"
        "\n* Update your current shell environment by sourcing from your .bashrc/.zshrc file."
    )

    if answers.get("dd_agent_logger"):
        farewell += "\n* Restart the Datadog Agent in order for it to accept firewall logs."

    if answers.get("dd_api_logger"):
        farewell += "\n* Ensure that environment variable DD_API_KEY is set to your Datadog API key."
        farewell += "\n* Verify any additional configuration needed to use this key (e.g., DD_SITE)."

    farewell += "\n\nGood luck!"

    return farewell


def _describe_log_level(action: FirewallAction) -> str:
    """
    Return a description of the given `action` considered as a log level.

    Args:
        action: A `FirewallAction` considered as a log level.

    Returns:
        A `str` description of which firewall actions are logged at the given level.
    """
    match action:
        case FirewallAction.ALLOW:
            return "Log allowed and blocked commands"
        case FirewallAction.BLOCK:
            return "Log only blocked commands"


def _get_home_dir_default() -> Optional[str]:
    """
    Resolve the default firewall cache directory from the user's home directory.

    Returns:
        A `str` representing the default firewall cache directory, which is contained
        inside the user's home directory, or `None` if the home directory cannot be resolved.
    """
    try:
        return str(Path.home() / ".scfw")
    except Exception as e:
        _log.warning(f"Failed to determine user's home directory: {e}")
        return None
