"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import json
import logging
import os

import dotenv

import scfw
from scfw.configure import DD_ENV, DD_LOG_LEVEL_VAR, DD_SERVICE, DD_SOURCE
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

_DD_LOG_LEVEL_DEFAULT = FirewallAction.BLOCK


dotenv.load_dotenv()


class DDLogFormatter(logging.Formatter):
    """
    A custom JSON formatter for firewall logs.
    """
    def format(self, record) -> str:
        """
        Format a log record as a JSON string.

        Args:
            record: The log record to be formatted.
        """
        log_record = {
            "source": DD_SOURCE,
            "service": DD_SERVICE,
            "version": scfw.__version__,
            "env": os.getenv("DD_ENV", DD_ENV),
        }

        for key in {"action", "created", "ecosystem", "msg", "targets"}:
            log_record[key] = record.__dict__[key]

        return json.dumps(log_record) + '\n'


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

        self._logger.info(
            f"Command '{' '.join(command)}' was {str(action).lower()}ed",
            extra={"action": str(action), "ecosystem": str(ecosystem), "targets": list(map(str, targets))}
        )
