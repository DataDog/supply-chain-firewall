"""
Implements the supply-chain firewall's `configure` subcommand.
"""

from argparse import Namespace
import inquirer # type: ignore
from pathlib import Path

_BLOCK_OPENER = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_CLOSER = "# END SCFW MANAGED BLOCK"

_GREETING = (
    "Thank you for using Datadog's supply-chain firewall, a tool for preventing\n"
    "the installation of malicious PyPI and npm packages.\n\n"
    "This script will walk you through setting up your environment to get the most\n"
    "out of the supply-chain firewall. It can be rerun at any time.\n"
)

_EPILOGUE = (
    "\nThe environment was successfully configured. Make sure to update your current\n"
    "shell environment by running:\n\n    source ~/.bashrc\n\nGood luck!"
)


def run_configure(args: Namespace) -> int:
    """
    Configure the environment for use with the supply-chain firewall.

    Args:
        args: A `Namespace` containing the parsed `configure` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    questions = [
        inquirer.Confirm(
            name='alias_pip',
            message="Would you like to set a shell alias to run all pip commands through the firewall?",
            default=False
        ),
        inquirer.Confirm(
            name='alias_npm',
            message="Would you like to set a shell alias to run all npm commands through the firewall?",
            default=False
        )
    ]

    print(_GREETING)

    config = inquirer.prompt(questions)
    if (formatted := _format_config(config)):
        with open(Path.home() / ".bashrc", 'a') as f:
            f.write(formatted)
        print(formatted)

    print(_EPILOGUE)

    return 0


def _format_config(config: dict) -> str:
    """
    Format the user-specified config into .rc file `str` content.

    Args:
        config: A `dict` containing the user-specified configuration options.

    Returns:
        A `str` containing the desired config for writing into a .rc file.
    """
    def enclose(formatted: str) -> str:
        return f"\n{_BLOCK_OPENER}{formatted}\n{_BLOCK_CLOSER}\n"

    formatted = ''

    if config["alias_pip"]:
        formatted += '\nalias pip="scfw run pip"'
    if config["alias_npm"]:
        formatted += '\nalias npm="scfw run npm"'

    return enclose(formatted) if formatted else formatted
