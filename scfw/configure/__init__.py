"""
Implements Supply-Chain Firewall's `configure` subcommand.
"""

from argparse import Namespace
import logging

from scfw.configure.dd_agent import configure_agent_logging, remove_agent_logging
from scfw.configure.env import update_config_files
from scfw.configure.interactive import GREETING, get_answers_interactive, get_farewell

_log = logging.getLogger(__name__)

DD_SOURCE = "scfw"
"""
Source value for Datadog logging.
"""

DD_SERVICE = "scfw"
"""
Service value for Datadog logging.
"""

DD_ENV = "dev"
"""
Default environment value for Datadog logging.
"""

DD_API_KEY_VAR = "DD_API_KEY"
"""
The environment variable under which the firewall looks for a Datadog API key.
"""

DD_LOG_LEVEL_VAR = "SCFW_DD_LOG_LEVEL"
"""
The environment variable under which the firewall looks for a Datadog log level setting.
"""

DD_AGENT_PORT_VAR = "SCFW_DD_AGENT_LOG_PORT"
"""
The environment variable under which the firewall looks for a port number on which to
forward firewall logs to the local Datadog Agent.
"""


def run_configure(args: Namespace) -> int:
    """
    Configure the environment for use with the supply-chain firewall.

    Args:
        args: A `Namespace` containing the parsed `configure` subcommand command line.

    Returns:
        An integer status code, 0 or 1.
    """
    try:
        if args.remove:
            # These options result in the firewall's configuration block being removed
            update_config_files({
                "alias_pip": False,
                "alias_npm": False,
                "dd_agent_port": None,
                "dd_api_key": None,
                "dd_log_level": None
            })
            remove_agent_logging()
            return 0

        interactive = not any(
            {args.alias_pip, args.alias_npm, args.dd_agent_port, args.dd_api_key, args.dd_log_level}
        )

        if interactive:
            print(GREETING)
            answers = get_answers_interactive()
        else:
            answers = vars(args)

        if not answers:
            return 0

        if (port := answers["dd_agent_port"]):
            configure_agent_logging(port)

        update_config_files(answers)

        if interactive:
            print(get_farewell(answers))

        return 0

    except Exception as e:
        _log.error(e)
        return 1
