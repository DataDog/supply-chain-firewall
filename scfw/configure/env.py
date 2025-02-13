"""
Provides utilities for configuring the environment (via `.rc` files) for using Supply-Chain Firewall.
"""

from pathlib import Path
import re
import os
import tempfile

from scfw.configure import DD_AGENT_PORT_VAR, DD_API_KEY_VAR, DD_LOG_LEVEL_VAR

_CONFIG_FILES = [".bashrc", ".zshrc"]

_BLOCK_START = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_END = "# END SCFW MANAGED BLOCK"


def update_config_files(answers: dict) -> None:
    """
    Update the firewall's configuration in all supported .rc files.

    Args:
        answers: A `dict` configuration options to format and write to each file.
    """
    for file in [Path.home() / file for file in _CONFIG_FILES]:
        if file.exists():
            _update_config_file(file, answers)


def _update_config_file(config_file: Path, answers: dict) -> None:
    """
    Update the firewall's section in the given configuration file.

    Args:
        config_file: A `Path` to the configuration file to update.
        answers: The `dict` of configuration options to write.
    """
    def enclose(config: str) -> str:
        return f"{_BLOCK_START}{config}\n{_BLOCK_END}"

    with open(config_file) as f:
        contents = f.read()

    config = _format_answers(answers)

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


def _format_answers(answers: dict) -> str:
    """
    Format configuration options into .rc file `str` content.

    Args:
        answers: A `dict` containing the user's selected configuration options.

    Returns:
        A `str` containing the desired configuration content for writing into a .rc file.
    """
    config = ''

    if answers["alias_pip"]:
        config += '\nalias pip="scfw run pip"'
    if answers["alias_npm"]:
        config += '\nalias npm="scfw run npm"'
    if answers["dd_agent_port"]:
        config += f'\nexport {DD_AGENT_PORT_VAR}="{answers["dd_agent_port"]}"'
    if answers["dd_api_key"]:
        config += f'\nexport {DD_API_KEY_VAR}="{answers["dd_api_key"]}"'
    if answers["dd_log_level"]:
        config += f'\nexport {DD_LOG_LEVEL_VAR}="{answers["dd_log_level"]}"'

    return config
