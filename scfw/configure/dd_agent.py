"""
Provides utilities for configuring the local Datadog Agent to receive logs from Supply-Chain Firewall.
"""

import json
import logging
from pathlib import Path
import shutil
import subprocess
from typing import Optional

from scfw.constants import DD_SERVICE, DD_SOURCE

_log = logging.getLogger(__name__)


def configure_agent_logging(port: str):
    """
    Configure a local Datadog Agent for accepting logs from the firewall.

    Args:
        port: The local port number where the firewall logs will be sent to the Agent.

    Raises:
        ValueError: An invalid port number was provided.
        RuntimeError: Failed to determine Datadog Agent configuration directory.
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

    scfw_config_dir = _dd_agent_scfw_config_dir()
    if not scfw_config_dir:
        raise RuntimeError("Failed to determine Datadog Agent configuration directory")

    scfw_config_file = scfw_config_dir / "conf.yaml"

    if not scfw_config_dir.is_dir():
        scfw_config_dir.mkdir()
        _log.info(f"Created directory {scfw_config_dir} for Datadog Agent configuration")
    with open(scfw_config_file, 'w') as f:
        f.write(config_file)
        _log.info(f"Wrote file {scfw_config_file} with Datadog Agent configuration")


def remove_agent_logging():
    """
    Remove Datadog Agent configuration for Supply-Chain Firewall, if it exists.
    """
    scfw_config_dir = _dd_agent_scfw_config_dir()
    if not (scfw_config_dir and scfw_config_dir.is_dir()):
        _log.info("No Datadog Agent configuration directory to remove")
        return

    try:
        shutil.rmtree(scfw_config_dir)
        _log.info(f"Removed directory {scfw_config_dir} with Datadog Agent configuration")
    except Exception as e:
        _log.warning(
            f"Failed to remove Datadog Agent configuration directory {scfw_config_dir}: {e}"
        )


def _dd_agent_scfw_config_dir() -> Optional[Path]:
    """
    Return the filesystem path to Supply-Chain Firewall's configuration directory
    for Datadog Agent log forwarding.

    Returns:
        A `Path` containing the local filesystem path to Supply-Chain Firewall's
        configuration directory for the Datadog Agent or `None` if the Agent binary
        is inaccessible or the Agent's global configuration directory (always the
        returned directory's parent) does not exist.

        The returned path is what Supply-Chain Firewall's configuration directory
        would be if it existed, but this function does not check that this directory
        actually exists. It is the caller's responsibility to do so.

    Raises:
        RuntimeError: Failed to query the Datadog Agent's status.
    """
    agent_path = shutil.which("datadog-agent")
    if not agent_path:
        _log.info("No Datadog Agent binary is accessible in the current environment")
        return None

    agent_config_dir = None
    try:
        agent_status = subprocess.run(
            [agent_path, "status", "--json"], check=True, text=True, capture_output=True
        )
        if (config_confd_path := json.loads(agent_status.stdout).get("config", {}).get("confd_path")):
            agent_config_dir = Path(config_confd_path).absolute()

    except Exception as e:
        raise RuntimeError(f"Failed to query Datadog Agent status: {e}")

    if not (agent_config_dir and agent_config_dir.is_dir()):
        _log.info("No Datadog Agent global configuration directory found")
        return None

    return agent_config_dir / "scfw.d"
