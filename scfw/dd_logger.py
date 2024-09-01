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
from dotenv import load_dotenv


load_dotenv()

_DD_API_KEY = os.getenv("DD_API_KEY", None)
_DD_ENV = os.getenv("DD_ENV", None)
_DD_SERVICE = os.getenv("DD_SERVICE", None)
_DD_VERSION = os.getenv("DD_VERSION", None)

_DD_APP_NAME = "scfw"
DD_LOG_NAME = "ddlog"


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
        targets = record.__dict__.get("targets", {})

        tags = {f"env:{_DD_ENV}"} | set(map(lambda e: f"target:{e}", targets))

        log_entry = self.format(record)
        body = HTTPLog(
            [
                HTTPLogItem(
                    ddtags=",".join(tags),
                    hostname=socket.gethostname(),
                    message=log_entry,
                    service=_DD_SERVICE,
                ),
            ]
        )

        configuration = Configuration()
        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)
            api_instance.submit_log(content_encoding=ContentEncoding.DEFLATE, body=body)


if _DD_API_KEY:
    if not _DD_SERVICE:
        os.environ["DD_SERVICE"] = _DD_SERVICE = _DD_APP_NAME
    if not _DD_ENV:
        os.environ["DD_ENV"] = _DD_ENV = "dev"
    if not _DD_VERSION:
        os.environ["DD_VERSION"] = _DD_VERSION = "0.1.0"

    ddlog = logging.getLogger(DD_LOG_NAME)
    ddlog.setLevel(logging.INFO)
    ddlog_handler = DDLogHandler()
    FORMAT = (
        "%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] - %(message)s"
    )
    ddlog_handler.setFormatter(logging.Formatter(FORMAT))
    ddlog.addHandler(ddlog_handler)
