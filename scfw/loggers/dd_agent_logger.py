"""
Configures a logger for sending firewall logs to a local Datadog Agent.
"""

import logging
import os
import socket

from scfw.configure import DD_AGENT_PORT_VAR
from scfw.logger import FirewallLogger
from scfw.loggers.dd_logger import DDLogFormatter, DDLogger

_log = logging.getLogger(__name__)

_DD_LOG_NAME = "dd_agent_log"


class _DDLogHandler(logging.Handler):
    def emit(self, record):
        """
        Format and send a log to the Datadog Agent.

        Args:
            record: The log record to be forwarded.
        """
        try:
            message = self.format(record).encode()

            agent_port = int(os.getenv(DD_AGENT_PORT_VAR))

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", agent_port))
            if s.send(message) != len(message):
                raise ValueError("Log send failed")
            s.close()

        except Exception as e:
            _log.warning(f"Failed to forward log to Datadog Agent: {e}")


# Configure a single logging handle for all `DDAgentLogger` instances to share
_handler = _DDLogHandler() if os.getenv(DD_AGENT_PORT_VAR) else logging.NullHandler()
_handler.setFormatter(DDLogFormatter())

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
