"""
Exports the currently discoverable set of client loggers implementing the
firewall's logging protocol.

One logger ships with the supply chain firewall by default: `DDLogger`,
which sends logs to Datadog. Firewall users may additionally provide
custom loggers according to their own logging needs.

The firewall discovers loggers at runtime via the following simple protocol.
The module implementing the custom logger must contain a function with the
following name and signature:

```
def load_logger() -> FirewallLogger
```

This `load_logger` function should return an instance of the custom logger
for the firewall's use. The module may then be placed in the directory configured
on the command line (in this directory otherwise) from which loggers should be
sourced for runtime import.
"""

import importlib
import logging
import os
import pkgutil
from typing import Optional

from scfw.logger import FirewallLogger

_log = logging.getLogger(__name__)


def get_firewall_loggers(source: Optional[str]) -> list[FirewallLogger]:
    """
    Return the currently discoverable set of client loggers.

    Args:
        source: An optional direction from which to source loggers.

    Returns:
        A `list` of the discovered `FirewallLogger`s.
    """
    loggers = []

    for _, module, _ in pkgutil.iter_modules([source if source else os.path.dirname(__file__)]):
        try:
            logger = importlib.import_module(module).load_logger()
            loggers.append(logger)
        except ModuleNotFoundError:
            _log.warning(f"Failed to load module {module} while collecting loggers")
        except AttributeError:
            _log.warning(f"Module {module} does not export a logger")

    return loggers
