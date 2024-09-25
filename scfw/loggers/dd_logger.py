"""
Configures a logger for sending firewall logs to Datadog.
"""

import logging
import os
import socket

from scfw.ecosystem import ECOSYSTEM
from scfw.logger import FirewallAction, FirewallLogger
from scfw.target import InstallTarget

from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.content_encoding import ContentEncoding
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem
import dotenv


class DDLogger(FirewallLogger):
    """
    An implementation of `FirewallLogger` for sending logs to Datadog.
    """
    def __init__(self):
        """
        Initialize a new `DDLogger`.
        """
        DD_LOG_NAME = "ddlog"
        DD_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] - %(message)s"

        dotenv.load_dotenv()
        handler = _DDLogHandler() if os.getenv("DD_API_KEY") else logging.NullHandler()
        handler.setFormatter(logging.Formatter(DD_LOG_FORMAT))

        ddlog = logging.getLogger(DD_LOG_NAME)
        ddlog.setLevel(logging.INFO)
        ddlog.addHandler(handler)

        self.logger = ddlog

    def log(
        self,
        action: FirewallAction,
        ecosystem: ECOSYSTEM,
        command: list[str],
        targets: list[InstallTarget]
    ):
        """
        Receive and log data about a completed firewall run.

        Args:
            action: The action taken by the firewall.
            ecosystem: The ecosystem of the inspected package manager command.
            command: The package manager command line provided to the firewall.
            targets: The installation targets relevant to firewall's action.
        """
        command = ' '.join(command)

        match action:
            case FirewallAction.Allow:
                message = f"Command '{command}' was allowed"
            case FirewallAction.Block:
                message = f"Command '{command}' was blocked"
            case FirewallAction.Abort:
                message = f"Command '{command}' was aborted"

        self.logger.info(
            message,
            extra={"ecosystem": ecosystem.value, "targets": map(str, targets)}
        )


class _DDLogHandler(logging.Handler):
    """
    A log handler for adding tags and forwarding firewall logs of blocked and
    permitted package installation requests to Datadog.

    In addition to USM tags, install targets are tagged with the `target` tag and included.
    """
    DD_SOURCE = "scfw"
    DD_ENV = "dev"
    DD_VERSION = "0.1.0"

    def __init__(self):
        super().__init__()

    def emit(self, record):
        """
        Format and send a log to Datadog.

        Args:
            record: The log record to be forwarded.
        """
        if not (env := os.getenv("DD_ENV")):
            env = self.DD_ENV
        if not (service := os.getenv("DD_SERVICE")):
            service = record.__dict__.get("ecosystem", self.DD_SOURCE)
        if not (version := os.getenv("DD_VERSION")):
            version = self.DD_VERSION

        usm_tags = {f"env:{env}", f"version:{version}"}

        targets = record.__dict__.get("targets", {})
        target_tags = set(map(lambda e: f"target:{e}", targets))

        body = HTTPLog(
            [
                HTTPLogItem(
                    ddsource=self.DD_SOURCE,
                    ddtags=",".join(usm_tags | target_tags),
                    hostname=socket.gethostname(),
                    message=self.format(record),
                    service=service,
                ),
            ]
        )

        configuration = Configuration()
        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)
            api_instance.submit_log(content_encoding=ContentEncoding.DEFLATE, body=body)
