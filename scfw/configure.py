"""
Implements the supply-chain firewall's `configure` subcommand.
"""

from argparse import Namespace
import inquirer  # type: ignore
import os
from pathlib import Path
import re
import tempfile

from scfw.logger import FirewallAction

DD_API_KEY_VAR = "DD_API_KEY"
"""
The environment variable under which the firewall looks for a Datadog API key.
"""

DD_LOG_LEVEL_VAR = "SCFW_DD_LOG_LEVEL"
"""
The environment variable under which the firewall looks for a Datadog log level setting.
"""

_CONFIG_FILES = [".bashrc", ".zshrc"]

_BLOCK_START = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_END = "# END SCFW MANAGED BLOCK"

_GREETING = (
    "Thank you for using scfw, the Supply-Chain Firewall by Datadog!\n\n"
    "scfw is a tool for preventing the installation of malicious PyPI and npm packages.\n\n"
    "This script will walk you through setting up your environment to get the most out\n"
    "of scfw. You can rerun this script at any time.\n"
)

_EPILOGUE = (
    "The environment was successfully configured. Make sure to update your current shell\n"
    "environment by running, e.g.:\n\n    source ~/.bashrc\n\nGood luck!"
)


def run_configure(args: Namespace) -> int:
    """
    Configure the environment for use with the supply-chain firewall.

    Args:
        args: A `Namespace` containing the parsed `configure` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    interactive = not any({args.alias_pip, args.alias_npm, args.dd_api_key, args.dd_log_level})

    if interactive:
        print(_GREETING)
        answers = inquirer.prompt(_get_questions())
    else:
        answers = vars(args)

    for file in [Path.home() / file for file in _CONFIG_FILES]:
        if file.exists():
            _update_config_file(file, _format_answers(answers))

    if interactive:
        print(_EPILOGUE)

    return 0


def _get_questions() -> list[inquirer.questions.Question]:
    """
    Return the list of configuration questions to ask the user.

    Returns:
        A `list[inquirer.Question]` of configuration questions to prompt the user
        for answers to. The list is guaranteed to be nonempty.
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
            name="enable_dd_logs",
            message="Would you like to enable sending firewall logs to Datadog?",
            default=False,
            ignore=lambda _: has_dd_api_key
        ),
        inquirer.Text(
            name="dd_api_key",
            message="Enter a Datadog API key",
            validate=lambda _, current: current != '',
            ignore=lambda answers: has_dd_api_key or not answers["enable_dd_logs"]
        ),
        inquirer.List(
            name="dd_log_level",
            message="Select the desired log level for Datadog logging",
            choices=[action.value for action in FirewallAction],
            ignore=lambda answers: not has_dd_api_key and not answers["enable_dd_logs"]
        )
    ]

    return questions


def _format_answers(answers: dict) -> str:
    """
    Format the user's answers into .rc file `str` configuration content.

    Args:
        answers: A `dict` containing the user's answers to the prompted questions.

    Returns:
        A `str` containing the desired configuration content for writing into a .rc file.
    """
    config = ''

    if answers["alias_pip"]:
        config += '\nalias pip="scfw run pip"'
    if answers["alias_npm"]:
        config += '\nalias npm="scfw run npm"'
    if answers["dd_api_key"]:
        config += f'\nexport {DD_API_KEY_VAR}="{answers["dd_api_key"]}"'
    if answers["dd_log_level"]:
        config += f'\nexport {DD_LOG_LEVEL_VAR}="{answers["dd_log_level"]}"'

    return config


def _update_config_file(config_file: Path, config: str) -> None:
    """
    Update the firewall's section in the given configuration file.

    Args:
        config_file: A `Path` to the configuration file to update.
        config: The new configuration to write.
    """
    def enclose(config: str) -> str:
        return f"{_BLOCK_START}{config}\n{_BLOCK_END}"

    with open(config_file) as f:
        contents = f.read()

    pattern = f"{_BLOCK_START}(.*?){_BLOCK_END}"
    if not config:
        pattern = f"\n{pattern}\n"

    updated = re.sub(pattern, enclose(config) if config else '', contents, flags=re.DOTALL)
    if updated == contents and config not in contents:
        updated = f"{contents}\n{enclose(config)}\n"

    temp_fd, temp_file = tempfile.mkstemp(text=True)
    temp_handle = os.fdopen(temp_fd, 'w')
    temp_handle.write(updated)
    temp_handle.close()

    os.rename(temp_file, config_file)
