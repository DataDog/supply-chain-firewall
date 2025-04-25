"""
Provides utilities for interactively accepting configuration options from the user.
"""

import os

import inquirer  # type: ignore

from scfw.configure.constants import DD_API_KEY_VAR
from scfw.logger import FirewallAction

GREETING = (
    "Thank you for using scfw, the Supply-Chain Firewall by Datadog!\n\n"
    "scfw is a tool for preventing the installation of malicious PyPI and npm packages.\n\n"
    "This script will walk you through setting up your environment to get the most out\n"
    "of scfw. You can rerun this script at any time.\n"
)

_DD_AGENT_DEFAULT_LOG_PORT = "10365"


def get_answers() -> dict:
    """
    Get the user's selection of configuration options in interactive mode.

    Returns:
        A `dict` containing the user's selected configuration options.
    """
    has_dd_api_key = os.getenv(DD_API_KEY_VAR) is not None

    questions = [
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
            name="dd_agent_logging",
            message="If you have the Datadog Agent installed locally, would you like to forward firewall logs to it?",
            default=False
        ),
        inquirer.Text(
            name="dd_agent_port",
            message=f"Enter the local port where the Agent will receive logs (default: {_DD_AGENT_DEFAULT_LOG_PORT})",
            ignore=lambda answers: not answers["dd_agent_logging"]
        ),
        inquirer.Confirm(
            name="dd_api_logging",
            message="Would you like to enable sending firewall logs to Datadog using an API key?",
            default=False,
            ignore=lambda answers: has_dd_api_key or answers["dd_agent_logging"]
        ),
        inquirer.Text(
            name="dd_api_key",
            message="Enter a Datadog API key",
            validate=lambda _, current: current != '',
            ignore=lambda answers: has_dd_api_key or not answers["dd_api_logging"]
        ),
        inquirer.List(
            name="dd_log_level",
            message="Select the desired log level for Datadog logging",
            choices=[(_describe_log_level(action), str(action)) for action in FirewallAction],
            ignore=lambda answers: not (answers["dd_agent_logging"] or has_dd_api_key or answers["dd_api_logging"])
        )
    ]

    answers = inquirer.prompt(questions)

    # Patch for inquirer's broken `default` option
    if answers.get("dd_agent_logging") and not answers.get("dd_agent_port"):
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

    if answers.get("dd_agent_logging"):
        farewell += "\n* Restart the Datadog Agent in order for it to accept firewall logs."

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
