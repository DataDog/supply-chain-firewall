"""
Provides utilities for configuring the environment (via `.rc` files) for using Supply-Chain Firewall.
"""

import logging
from pathlib import Path
import re
import os
import tempfile

from scfw.configure.constants import DD_AGENT_PORT_VAR, DD_API_KEY_VAR, DD_LOG_LEVEL_VAR, SCFW_HOME_VAR

_log = logging.getLogger(__name__)

_CONFIG_FILES = [".bashrc", ".zshrc"]

_BLOCK_START = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_END = "# END SCFW MANAGED BLOCK"


def update_config_files(answers: dict):
    """
    Update the firewall's configuration in all supported .rc files.

    Args:
        answers: A `dict` configuration options to format and write to each file.
    """
    for file in [Path.home() / file for file in _CONFIG_FILES]:
        if file.exists():
            _update_config_file(file, answers)


def _update_config_file(config_file: Path, answers: dict):
    """
    Update the firewall's section in the given configuration file.

    Args:
        config_file: A `Path` to the configuration file to update.
        answers: The `dict` of configuration options to write.
    """
    def enclose(config: str) -> str:
        return f"{_BLOCK_START}{config}\n{_BLOCK_END}"

    def overwrite_file(f, contents: str):
        f.truncate(0)
        f.write(contents)

    config = _format_answers(answers)

    pattern = f"{_BLOCK_START}(.*?){_BLOCK_END}"
    if not config:
        pattern = f"\n{pattern}\n"

    # Make a backup copy of the original file in case something goes wrong
    # during the update and we are unable to restore the original ourselves
    temp_fd, temp_file = tempfile.mkstemp(text=True)

    with open(config_file, "r+") as f:
        original = f.read()

        temp_handle = os.fdopen(temp_fd, 'w')
        temp_handle.write(original)
        temp_handle.close()

        updated = re.sub(pattern, enclose(config) if config else '', original, flags=re.DOTALL)
        if updated == original and config not in original:
            updated = f"{original}\n{enclose(config)}\n"

        try:
            overwrite_file(f, updated)
        except Exception as e:
            _log.warning(f"Failed to add configuration to {config_file}: {e}")
            try:
                overwrite_file(f, original)
            except Exception:
                raise RuntimeError(
                    f"Failed while restoring {config_file} after failed configuration update: "
                    f"a backup copy of the original file contents is in {temp_file}"
                )

    os.remove(temp_file)


def _format_answers(answers: dict) -> str:
    """
    Format configuration options into .rc file `str` content.

    Args:
        answers: A `dict` containing the user's selected configuration options.

    Returns:
        A `str` containing the desired configuration content for writing into a .rc file.
    """
    config = ''

    if answers.get("alias_npm"):
        config += '\nalias npm="scfw run npm"'
    if answers.get("alias_pip"):
        config += '\nalias pip="scfw run pip"'
    if answers.get("alias_poetry"):
        config += '\nalias poetry="scfw run poetry"'
    if (dd_agent_port := answers.get("dd_agent_port")):
        config += f'\nexport {DD_AGENT_PORT_VAR}="{dd_agent_port}"'
    if (dd_api_key := answers.get("dd_api_key")):
        config += f'\nexport {DD_API_KEY_VAR}="{dd_api_key}"'
    if (dd_log_level := answers.get("dd_log_level")):
        config += f'\nexport {DD_LOG_LEVEL_VAR}="{dd_log_level}"'
    if (scfw_home := answers.get("scfw_home")):
        config += f'\nexport {SCFW_HOME_VAR}="{scfw_home}"'

    return config
