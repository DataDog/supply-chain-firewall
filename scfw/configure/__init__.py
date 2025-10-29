"""
Implements Supply-Chain Firewall's `configure` subcommand.
"""

from argparse import Namespace
import logging

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
        An integer status code indicating normal exit.
    """
    if args.remove:
        try:
            dd_agent.remove_agent_logging()
        except Exception as e:
            _log.warning(f"Failed to remove Datadog Agent configuration: {e}")

        env.remove_config()

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
        args.dd_log_level,
        args.scfw_home,
    })

    if is_interactive:
        print(GREETING)
        answers = interactive.get_answers()
    else:
        answers = vars(args)

    if not answers:
        return 0

    if (port := answers.get("dd_agent_port")):
        try:
            dd_agent.configure_agent_logging(port)
        except Exception as e:
            _log.warning(f"Failed to configure Datadog Agent for Supply-Chain Firewall: {e}")
            # Don't set the Agent port environment variable if Agent configuration failed
            answers["dd_agent_port"] = None

    env.update_config_files(answers)

    if is_interactive:
        print(interactive.get_farewell(answers))

    return 0
