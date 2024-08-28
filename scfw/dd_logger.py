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

DD_API_KEY = os.getenv("DD_API_KEY", None)
DD_ENV = os.getenv("DD_ENV", None)
DD_SERVICE = os.getenv("DD_SERVICE", None)
DD_VERSION = os.getenv("DD_VERSION", None)

APP_NAME = "scfw"
DD_LOG_NAME = "ddlog"


class DDLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        targets = record.__dict__.get("targets", {})

        tags = {f"env:{DD_ENV}"} | set(map(lambda e: f"target:{e}", targets))

        log_entry = self.format(record)
        body = HTTPLog(
            [
                HTTPLogItem(
                    ddtags=",".join(tags),
                    hostname=socket.gethostname(),
                    message=log_entry,
                    service=DD_SERVICE,
                ),
            ]
        )

        configuration = Configuration()
        with ApiClient(configuration) as api_client:
            api_instance = LogsApi(api_client)
            api_instance.submit_log(content_encoding=ContentEncoding.DEFLATE, body=body)


if DD_API_KEY:
    if not DD_SERVICE:
        os.environ["DD_SERVICE"] = DD_SERVICE = APP_NAME
    if not DD_ENV:
        os.environ["DD_ENV"] = DD_ENV = "dev"
    if not DD_VERSION:
        os.environ["DD_VERSION"] = DD_VERSION = "0.1.0"

    ddlog = logging.getLogger(DD_LOG_NAME)
    ddlog.setLevel(logging.INFO)
    ddlog_handler = DDLogHandler()
    FORMAT = (
        "%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] - %(message)s"
    )
    ddlog_handler.setFormatter(logging.Formatter(FORMAT))
    ddlog.addHandler(ddlog_handler)
