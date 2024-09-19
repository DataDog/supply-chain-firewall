"""
Configures a logger for sending firewall logs to Datadog.
"""

import logging
import os
import socket

from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.content_encoding import ContentEncoding
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem
import dotenv

DD_LOG_NAME = "ddlog"

_DD_SOURCE = "scfw"
_DD_ENV_DEFAULT = "dev"
_DD_SERVICE_DEFAULT = _DD_SOURCE
_DD_VERSION_DEFAULT = "0.1.0"


class _DDLogHandler(logging.Handler):
    """
    A log handler for adding tags and forwarding firewall logs of blocked and
    permitted package installation requests to Datadog.

    In addition to USM tags, install targets are tagged with the `target` tag and included.
    """
    def __init__(self):
        super().__init__()

    def emit(self, record):
        """
        Format and send a log to Datadog.

        Args:
            record: The log record to be forwarded.
        """
        usm_tags = {f"env:{os.getenv('DD_ENV')}", f"version:{os.getenv('DD_VERSION')}"}

        targets = record.__dict__.get("targets", {})
        target_tags = set(map(lambda e: f"target:{e}", targets))

        body = HTTPLog(
            [
                HTTPLogItem(
                    ddsource=_DD_SOURCE,
                    ddtags=",".join(usm_tags | target_tags),
                    hostname=socket.gethostname(),
                    message=self.format(record),
                    service=os.getenv("DD_SERVICE"),
                ),
            ]
        )

        configuration = Configuration()
        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)
            api_instance.submit_log(content_encoding=ContentEncoding.DEFLATE, body=body)


dotenv.load_dotenv()

if os.getenv("DD_API_KEY"):
    log = logging.getLogger(__name__)
    log.info("Datadog API key detected: Datadog log forwarding enabled")

    if not os.getenv("DD_ENV"):
        os.environ["DD_ENV"] = _DD_ENV_DEFAULT
    if not os.getenv("DD_SERVICE"):
        os.environ["DD_SERVICE"] = _DD_SERVICE_DEFAULT
    if not os.getenv("DD_VERSION"):
        os.environ["DD_VERSION"] = _DD_VERSION_DEFAULT

    ddlog = logging.getLogger(DD_LOG_NAME)
    ddlog.setLevel(logging.INFO)
    ddlog_handler = _DDLogHandler()
    FORMAT = (
        "%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] - %(message)s"
    )
    ddlog_handler.setFormatter(logging.Formatter(FORMAT))
    ddlog.addHandler(ddlog_handler)
