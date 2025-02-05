"""
Configures a logger for sending firewall logs to a local Datadog Agent.
"""

import json
import logging
import os
import socket

import dotenv

import scfw
from scfw.configure import DD_AGENT_LOG_VAR, DD_AGENT_PORT
from scfw.logger import FirewallLogger
from scfw.loggers.dd_logger import DDLogger

_log = logging.getLogger(__name__)

_DD_LOG_NAME = "dd_agent_log"


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


class DDAgentLogger(DDLogger):
    """
    An implementation of `FirewallLogger` for sending logs to a local Datadog Agent.
    """
    def __init__(self):
        """
        Initialize a new `DDAgentLogger`.
        """
        super().__init__(_ddlog)


def load_logger() -> FirewallLogger:
    """
    Export `DDAgentLogger` for discovery by the firewall.

    Returns:
        A `DDAgentLogger` for use in a run of the firewall.
    """
    return DDAgentLogger()
