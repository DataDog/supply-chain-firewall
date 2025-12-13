"""
Provides a `FirewallLogger` class for writing a local JSON Lines log file.
"""

import logging
import os
from pathlib import Path

from scfw.constants import SCFW_HOME_VAR
from scfw.logger import FirewallAction, FirewallLogger
from scfw.loggers.dd_logger import DDLogFormatter, DDLogger

_log = logging.getLogger(__name__)

LOG_FILE_NAME = "scfw.log"
"""
The default local log file within `SCFW_HOME`.
"""

LOG_FILE_VAR = "SCFW_LOG_FILE"
"""
The environment variable under which the local file logger looks for a log file
to write to instead of using the default file.
"""


# Configure a single logging handle for all `FileLogger` instances to share
_handler: logging.Handler = logging.NullHandler()
if (log_file := os.getenv(LOG_FILE_VAR)):
    _handler = logging.FileHandler(log_file)
elif (scfw_home := os.getenv(SCFW_HOME_VAR)):
    _handler = logging.FileHandler(Path(scfw_home) / LOG_FILE_NAME)
else:
    _log.warning(
        f"No local log file configured: consider setting {LOG_FILE_VAR} or {SCFW_HOME_VAR}"
    )
_handler.setFormatter(DDLogFormatter())

_file_log = logging.getLogger("file_logger")
_file_log.setLevel(logging.INFO)
_file_log.addHandler(_handler)


class FileLogger(DDLogger):
    """
    An implementation of `FirewallLogger` for writing a local JSON lines log file.
    """
    def __init__(self):
        """
        Initialize a new `FileLogger`.
        """
        self._logger = _file_log

        # Ignore the configured log level so that everything is logged to file
        self._level = FirewallAction.ALLOW


def load_logger() -> FirewallLogger:
    """
    Export `FileLogger` for discovery by Supply-Chain Firewall.

    Returns:
        A `FileLogger` for use in a run of Supply-Chain Firewall.
    """
    return FileLogger()
