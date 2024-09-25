"""
Exports a set of client loggers implementing the firewall's logging protocol.
"""

from scfw.logger import FirewallLogger
from scfw.loggers.dd_logger import DDLogger


def get_firewall_loggers() -> list[FirewallLogger]:
    """
    Return the current set of available client loggers.

    Returns:
        A `list` of the currently available `FirewallLogger`s.
    """
    return [DDLogger()]
