"""
Provides utilities for configuring the environment (via `.rc` files) for using Supply-Chain Firewall.
"""

import logging
from pathlib import Path
import re

from scfw.constants import DD_AGENT_PORT_VAR, DD_API_KEY_VAR, DD_LOG_LEVEL_VAR, SCFW_HOME_VAR

_log = logging.getLogger(__name__)

_CONFIG_FILES = [".bashrc", ".zshrc"]

_BLOCK_START = "# BEGIN SCFW MANAGED BLOCK"
_BLOCK_END = "# END SCFW MANAGED BLOCK"


def remove_config():
    """
    Remove Supply-Chain Firewall configuration from all supported files.
    """
    # These options result in the firewall's configuration block being removed
    update_config_files({
        "alias_npm": False,
        "alias_pip": False,
        "alias_poetry": False,
        "dd_agent_port": None,
        "dd_api_key": None,
        "dd_log_level": None,
        "scfw_home": None,
    })


def update_config_files(answers: dict):
    """
    Update the Supply-Chain Firewall configuration in all supported files.

    Args:
        answers: A `dict` of configuration options to format and write to each file.
    """
    scfw_config = _format_answers(answers)

    for config_file in [Path.home() / file for file in _CONFIG_FILES]:
        if not config_file.exists():
            _log.info(f"Skipped adding configuration to file {config_file}: file does not already exist")
            continue

        try:
            _update_config_file(config_file, scfw_config)
            _log.info(f"Successfully updated configuration in file {config_file}")

        except Exception as e:
            _log.warning(f"Failed to update configuration in file {config_file}: {e}")


def _update_config_file(config_file: Path, scfw_config: str):
    """
    Update the Supply-Chain Firewall configuration in the given file.

    Args:
        config_file: A `Path` to the configuration file to update.
        scfw_config: A `str` containing the formatted configuration options to write.
    """
    scfw_block = f"{_BLOCK_START}\n{scfw_config}{_BLOCK_END}" if scfw_config else ""

    with open(config_file, "r+") as f:
        original_config = f.read()

        updated_config = re.sub(f"{_BLOCK_START}(.*?){_BLOCK_END}", scfw_block, original_config, flags=re.DOTALL)
        if updated_config == original_config and scfw_config not in original_config:
            updated_config = f"{original_config}\n{scfw_block}\n"

        f.seek(0)
        f.write(updated_config)
        f.truncate()


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
        config += 'alias npm="scfw run npm"\n'
    if answers.get("alias_pip"):
        config += 'alias pip="scfw run pip"\n'
    if answers.get("alias_poetry"):
        config += 'alias poetry="scfw run poetry"\n'
    if (dd_agent_port := answers.get("dd_agent_port")):
        config += f'export {DD_AGENT_PORT_VAR}="{dd_agent_port}"\n'
    if (dd_api_key := answers.get("dd_api_key")):
        config += f'export {DD_API_KEY_VAR}="{dd_api_key}"\n'
    if (dd_log_level := answers.get("dd_log_level")):
        config += f'export {DD_LOG_LEVEL_VAR}="{dd_log_level}"\n'
    if (scfw_home := answers.get("scfw_home")):
        config += f'export {SCFW_HOME_VAR}="{scfw_home}"\n'

    return config
