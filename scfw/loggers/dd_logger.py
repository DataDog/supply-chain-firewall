"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import logging
import os

import dotenv

from scfw.configure import DD_LOG_LEVEL_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

_DD_LOG_LEVEL_DEFAULT = FirewallAction.BLOCK


dotenv.load_dotenv()


class DDLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to Datadog.
    """
    def __init__(self, logger: logging.Logger):
        """
        Initialize a new `DDLogger`.

        Args:
            logger: A configured log handle to which logs will be written.
        """
        self._logger = logger

        try:
            self._level = FirewallAction(os.getenv(DD_LOG_LEVEL_VAR))
        except ValueError:
            _log.warning(f"Undefined or invalid Datadog log level: using default level {_DD_LOG_LEVEL_DEFAULT}")
            self._level = _DD_LOG_LEVEL_DEFAULT

    def log(
        self,
        action: FirewallAction,
        ecosystem: ECOSYSTEM,
        command: list[str],
        targets: list[InstallTarget]
    ):
        """
        Receive and log data about a completed firewall run.

        Args:
            action: The action taken by the firewall.
            ecosystem: The ecosystem of the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets: The installation targets relevant to firewall's action.
        """
        if not self._level or action < self._level:
            return

        match action:
            case FirewallAction.ALLOW:
                message = f"Command '{' '.join(command)}' was allowed"
            case FirewallAction.ABORT:
                message = f"Command '{' '.join(command)}' was aborted"
            case FirewallAction.BLOCK:
                message = f"Command '{' '.join(command)}' was blocked"

        self._logger.info(
            message,
            extra={"action": str(action), "ecosystem": str(ecosystem), "targets": list(map(str, targets))}
        )
