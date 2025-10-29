"""
Provides utilities for configuring the local Datadog Agent to receive logs from Supply-Chain Firewall.
"""

import json
import logging
from pathlib import Path
import shutil
import subprocess

from scfw.constants import DD_SERVICE, DD_SOURCE

_log = logging.getLogger(__name__)


def configure_agent_logging(port: str):
    """
    Configure a local Datadog Agent for accepting logs from the firewall.

    Args:
        port: The local port number where the firewall logs will be sent to the Agent.

    Raises:
        ValueError: An invalid port number was provided.
        RuntimeError: An error occurred while querying the Agent's status.
    """
    if not (0 < int(port) < 2 ** 16):
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
        _log.info(f"Created directory {scfw_config_dir} for Datadog Agent configuration")
    with open(scfw_config_file, 'w') as f:
        f.write(config_file)
        _log.info(f"Wrote file {scfw_config_file} with Datadog Agent configuration")


def remove_agent_logging():
    """
    Remove Datadog Agent configuration for Supply-Chain Firewall, if it exists.

    Raises:
        RuntimeError: An error occurred while attempting to remove the configuration directory.
    """
    try:
        scfw_config_dir = _dd_agent_scfw_config_dir()
    except FileNotFoundError:
        _log.info("Datadog Agent binary is not available; no configuration to remove")
        return

    if not scfw_config_dir.is_dir():
        _log.info("No Datadog Agent configuration directory to remove")
        return

    try:
        shutil.rmtree(scfw_config_dir)
        _log.info(f"Deleted directory {scfw_config_dir} with Datadog Agent configuration")
    except Exception:
        raise RuntimeError(
            f"Failed to delete directory {scfw_config_dir} with Datadog Agent configuration for Supply-Chain Firewall"
        )


def _dd_agent_scfw_config_dir() -> Path:
    """
    Get the filesystem path to the firewall's configuration directory for
    Datadog Agent log forwarding.

    Returns:
        A `Path` indicating the absolute filesystem path to this directory.

    Raises:
        RuntimeError:
            * Unable to query Datadog Agent status to read the location of its global
              configuration directory
            * Datadog Agent global configuration directory is not set or does not exist
        ValueError: Failed to parse Datadog Agent status JSON report.
    """
    try:
        agent_status = subprocess.run(
            ["datadog-agent", "status", "--json"], check=True, text=True, capture_output=True
        )
        config_confd_path = json.loads(agent_status.stdout).get("config", {}).get("confd_path")
        agent_config_dir = Path(config_confd_path) if config_confd_path else None

    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Unable to query Datadog Agent status: please ensure the Agent is running. "
            "Linux users may need sudo to run this command."
        )

    except json.JSONDecodeError:
        raise ValueError("Failed to parse Datadog Agent status report as JSON")

    if not (agent_config_dir and agent_config_dir.is_dir()):
        raise RuntimeError(
            "Datadog Agent global configuration directory is not set or does not exist"
        )

    return agent_config_dir / "scfw.d"
