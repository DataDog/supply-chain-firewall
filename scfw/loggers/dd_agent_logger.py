"""
Configures a logger for sending firewall logs to a local Datadog Agent.
"""

import logging
import os
import socket

from scfw.constants import DD_AGENT_PORT_VAR
from scfw.logger import FirewallLogger
from scfw.loggers.dd_logger import DDLogFormatter, DDLogger

_log = logging.getLogger(__name__)

_DD_LOG_NAME = "dd_agent_log"


class _DDLogHandler(logging.Handler):
    def __init__(self, agent_port: int):
        """
        Initialize a new `_DDLogHandler` instance.

        Args:
            agent_port:
                The port number where the Datadog Agent has been independently configured
                to receive logs from Supply-Chain Firewall.

        Raises:
            ValueError: An invalid port number was given.
        """
        if not 0 < agent_port < 2 ** 16:
            raise ValueError(f"Invalid port number {agent_port}")
        self._agent_port = agent_port

        super().__init__()

    def emit(self, record):
        """
        Format and send a log to the Datadog Agent.

        Args:
            record: The log record to be forwarded.

        Raises:
            RuntimeError: Failed to forward log to Datadog Agent.
        """
        try:
            message = self.format(record).encode()

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", self._agent_port))
            if s.send(message) != len(message):
                raise ValueError("Failed to send log message over local socket")
            s.close()

        except Exception as e:
            raise RuntimeError(f"Failed to forward log to Datadog Agent: {e}")


# Configure a single logging handle for all `DDAgentLogger` instances to share
_handler: logging.Handler = logging.NullHandler()
if (dd_agent_port := os.getenv(DD_AGENT_PORT_VAR)):
    try:
        _handler = _DDLogHandler(int(dd_agent_port))
    except Exception as e:
        _log.warning(f"Failed to initialize Datadog Agent logger: {e}")
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
