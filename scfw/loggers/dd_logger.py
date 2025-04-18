"""
Provides a `FirewallLogger` class for sending logs to Datadog.
"""

import getpass
import json
import logging
import os
import socket

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
            "hostname": socket.gethostname(),
        }

        try:
            log_record["username"] = getpass.getuser()
        except Exception as e:
            _log.warning(f"Failed to query username: {e}")

        # The `created` and `msg` attributes are provided by `logging.LogRecord`
        for key in {"action", "created", "ecosystem", "executable", "msg", "targets", "warned"}:
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
        self._level = _DD_LOG_LEVEL_DEFAULT

        try:
            if (dd_log_level := os.getenv(DD_LOG_LEVEL_VAR)) is not None:
                self._level = FirewallAction.from_string(dd_log_level)
        except ValueError:
            _log.warning(f"Undefined or invalid Datadog log level: using default level {_DD_LOG_LEVEL_DEFAULT}")

    def log(
        self,
        ecosystem: ECOSYSTEM,
        executable: str,
        command: list[str],
        targets: list[InstallTarget],
        action: FirewallAction,
        warned: bool
    ):
        """
        Receive and log data about a completed firewall run.

        Args:
            ecosystem: The ecosystem of the inspected package manager command.
            executable: The executable used to execute the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets: The installation targets relevant to firewall's action.
            action: The action taken by the firewall.
            warned: Indicates whether the user was warned about findings and prompted for approval.
        """
        if not self._level or action < self._level:
            return

        self._logger.info(
            f"Command '{' '.join(command)}' was {str(action).lower()}ed",
            extra={
                "ecosystem": str(ecosystem),
                "executable": executable,
                "targets": list(map(str, targets)),
                "action": str(action),
                "warned": warned,
            }
        )
