"""
Implements Supply-Chain Firewall's `configure` subcommand.
"""

from argparse import Namespace
import logging

from scfw.configure.constants import *  # noqa
import scfw.configure.dd_agent as dd_agent
import scfw.configure.env as env
import scfw.configure.interactive as interactive
from scfw.configure.interactive import GREETING

_log = logging.getLogger(__name__)


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
            env.update_config_files({
                "alias_npm": False,
                "alias_pip": False,
                "alias_poetry": False,
                "dd_agent_port": None,
                "dd_api_key": None,
                "dd_log_level": None
            })
            dd_agent.remove_agent_logging()
            print(
                "All Supply-Chain Firewall-managed configuration has been removed from your environment."
                "\n\nPost-removal tasks:"
                "\n* Update your current shell environment by sourcing from your .bashrc/.zshrc file."
                "\n* If you had previously configured Datadog Agent log forwarding, restart the Agent."
            )
            return 0

        # The CLI parser guarantees that all of these arguments are present
        is_interactive = not any({
            args.alias_npm,
            args.alias_pip,
            args.alias_poetry,
            args.dd_agent_port,
            args.dd_api_key,
            args.dd_log_level
        })

        if is_interactive:
            print(GREETING)
            answers = interactive.get_answers()
        else:
            answers = vars(args)

        if not answers:
            return 0

        if (port := answers.get("dd_agent_port")):
            dd_agent.configure_agent_logging(port)

        env.update_config_files(answers)

        if is_interactive:
            print(interactive.get_farewell(answers))

        return 0

    except Exception as e:
        _log.error(e)
        return 1
