import os
import sys
import logging
import socket

from dotenv import load_dotenv
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.content_encoding import ContentEncoding
from datadog_api_client.v2.model.http_log import HTTPLog
from datadog_api_client.v2.model.http_log_item import HTTPLogItem


load_dotenv()

DD_API_KEY= os.getenv("DD_API_KEY",None)
DD_ENV = os.getenv("DD_ENV",None)
DD_SERVICE = os.getenv("DD_SERVICE",None)
DD_VERSION = os.getenv("DD_VERSION",None)

LOG_DD = "ddglog"
APPNAME = "scfw"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
stderrHandler = logging.StreamHandler(stream=sys.stderr)
stderrHandler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(stderrHandler)


class DDLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        tags = {f"env:{DD_ENV}"}
        extra_tags = record.__dict__.get("tags", {})

        tags |= set(map(lambda e: f"target:{e}",extra_tags))

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
    logger.info("Datadog logging enabled")

    if not DD_SERVICE:
        os.environ["DD_SERVICE"] = DD_SERVICE = APPNAME
    if not DD_ENV:
        os.environ["DD_ENV"] = DD_ENV = "dev"
    if not DD_VERSION:
        os.environ["DD_VERSION"] = DD_VERSION = "0.1.0"

    ddlog = logging.getLogger(LOG_DD)
    ddlog.setLevel(logging.INFO)
    ddlog_handler = DDLogHandler()
    FORMAT = ('%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] '
          '- %(message)s')
    ddlog_handler.setFormatter(logging.Formatter(FORMAT))
    ddlog.addHandler(ddlog_handler)
