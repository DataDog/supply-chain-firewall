"""
Users of Supply Chain Firewall may want to use custom loggers according to their
own logging needs.  This module contains a template for writing a custom logger.

Supply Chain Firewall discovers loggers at runtime via the following simple protocol.
The module implementing the custom logger must contain a function with the following
name and signature:

```
def load_logger() -> FirewallLogger
```

This `load_logger` function should return an instance of the custom logger for
Supply Chain Firewall's use. The module may then be placed in the `scfw/loggers`
directory for runtime import, no further modification required. Make sure to reinstall
the `scfw` package after doing so.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallLogger, FirewallRunSummary
from scfw.report import VerificationReport


class CustomFirewallLogger(FirewallLogger):
    def log_firewall_run(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        run_summary: FirewallRunSummary,
    ):
        return

    def log_audit(
        self,
        ecosystem: ECOSYSTEM,
        package_manager: str,
        executable: str,
        report: VerificationReport,
    ):
        return


def load_logger() -> FirewallLogger:
    return CustomFirewallLogger()
