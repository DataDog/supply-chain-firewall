"""
Provides utilities for configuring the local Datadog Agent to receive logs from Supply-Chain Firewall.
"""

import json
from pathlib import Path
import shutil
import subprocess

from scfw.configure.constants import DD_SERVICE, DD_SOURCE


def configure_agent_logging(port: str):
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

    scfw_config_dir = _dd_agent_scfw_config_dir()
    scfw_config_file = scfw_config_dir / "conf.yaml"

    if not scfw_config_dir.is_dir():
        scfw_config_dir.mkdir()
    with open(scfw_config_file, 'w') as f:
        f.write(config_file)


def remove_agent_logging():
    """
    Remove Datadog Agent configuration for Supply-Chain Firewall, if it exists.

    Raises:
        RuntimeError: An error occurred while attempting to remove the configuration directory.
    """
    scfw_config_dir = _dd_agent_scfw_config_dir()

    if not scfw_config_dir.is_dir():
        return

    try:
        shutil.rmtree(scfw_config_dir)
    except Exception:
        raise RuntimeError(
            "Failed to delete Datadog Agent configuration directory for Supply-Chain Firewall"
        )


def _dd_agent_scfw_config_dir() -> Path:
    """
    Get the filesystem path to the firewall's configuration directory for
    Datadog Agent log forwarding.

    Returns:
        A `Path` indicating the absolute filesystem path to this directory.

    Raises:
        RuntimeError:
            Unable to query Datadog Agent status to read the location of its
            global configuration directory.
    """
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

    return Path(agent_config_dir) / "scfw.d"
