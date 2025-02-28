"""
Configures a logger for sending firewall logs to Datadog's API over HTTP.
"""

import logging
import os

from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.content_encoding import ContentEncoding
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem

import scfw
from scfw.configure import DD_API_KEY_VAR, DD_ENV, DD_SERVICE, DD_SOURCE
from scfw.logger import FirewallLogger
from scfw.loggers.dd_logger import DDLogFormatter, DDLogger

_DD_LOG_NAME = "dd_api_log"


class _DDLogHandler(logging.Handler):
    """
    A log handler for adding tags and forwarding firewall logs of blocked and
    permitted package installation requests to the Datadog API.

    In addition to USM tags, install targets are tagged with the `target` tag and included.
    """
    def emit(self, record):
        """
        Format and send a log to Datadog.

        Args:
            record: The log record to be forwarded.
        """
        usm_tags = {
            f"env:{os.getenv('DD_ENV', DD_ENV)}",
            f"version:{scfw.__version__}"
        }

        targets = record.__dict__.get("targets", {})
        target_tags = set(map(lambda e: f"target:{e}", targets))

        body = HTTPLog(
            [
                HTTPLogItem(
                    ddsource=DD_SOURCE,
                    ddtags=",".join(usm_tags | target_tags),
                    message=self.format(record),
                    service=DD_SERVICE,
                ),
            ]
        )

        configuration = Configuration()
        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)
            api_instance.submit_log(content_encoding=ContentEncoding.DEFLATE, body=body)


# Configure a single logging handle for all `DDAPILogger` instances to share
_handler = _DDLogHandler() if os.getenv(DD_API_KEY_VAR) else logging.NullHandler()
_handler.setFormatter(DDLogFormatter())

_ddlog = logging.getLogger(_DD_LOG_NAME)
_ddlog.setLevel(logging.INFO)
_ddlog.addHandler(_handler)


class DDAPILogger(DDLogger):
    """
    An implementation of `FirewallLogger` for sending logs to the Datadog API.
    """
    def __init__(self):
        """
        Initialize a new `DDAPILogger`.
        """
        super().__init__(_ddlog)


def load_logger() -> FirewallLogger:
    """
    Export `DDAPILogger` for discovery by the firewall.

    Returns:
        A `DDAPILogger` for use in a run of the firewall.
    """
    return DDAPILogger()
