"""
Configures a logger for sending firewall logs to a local Datadog Agent.
"""

import json
import logging
import os
import socket

import dotenv

import scfw
from scfw.configure import DD_AGENT_LOG_VAR, DD_AGENT_PORT, DD_LOG_LEVEL_VAR
from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget

_log = logging.getLogger(__name__)

_DD_LOG_NAME = "dd_agent_log"

_DD_LOG_LEVEL_DEFAULT = FirewallAction.BLOCK


class _DDLogFormatter(logging.Formatter):
    """
    A custom JSON formatter for firewall logs.
    """
    DD_ENV = "dev"
    DD_VERSION = scfw.__version__
    DD_SERVICE = DD_SOURCE = "scfw"

    def format(self, record) -> str:
        """
        Format a log record as a JSON string.

        Args:
            record: The log record to be formatted.
        """
        log_record = {
            "source": self.DD_SOURCE,
            "service": self.DD_SERVICE,
            "version": self.DD_VERSION
        }

        env = os.getenv("DD_ENV")
        log_record["env"] = env if env else self.DD_ENV

        for key in {"action", "created", "ecosystem", "msg", "targets"}:
            log_record[key] = record.__dict__[key]

        return json.dumps(log_record) + '\n'


class _DDLogHandler(logging.Handler):
    """
    A custom log handler for forwarding firewall logs to a local Datadog Agent.
    """
    def emit(self, record):
        """
        Format and send a log to the Datadog Agent.

        Args:
            record: The log record to be forwarded.
        """
        message = self.format(record).encode()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", DD_AGENT_PORT))
        if s.send(message) != len(message):
            _log.warning("Failed to log firewall action to Datadog Agent")
        s.close()


# Configure a single logging handle for all `DDAgentLogger` instances to share
dotenv.load_dotenv()
_handler = _DDLogHandler() if os.getenv(DD_AGENT_LOG_VAR) else logging.NullHandler()
_handler.setFormatter(_DDLogFormatter())

_ddlog = logging.getLogger(_DD_LOG_NAME)
_ddlog.setLevel(logging.INFO)
_ddlog.addHandler(_handler)


class DDAgentLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to a local Datadog Agent.
    """
    def __init__(self):
        """
        Initialize a new `DDAgentLogger`.
        """
        self._logger = _ddlog

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


def load_logger() -> FirewallLogger:
    """
    Export `DDAgentLogger` for discovery by the firewall.

    Returns:
        A `DDAgentLogger` for use in a run of the firewall.
    """
    return DDAgentLogger()
