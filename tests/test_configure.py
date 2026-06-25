"""
Tests of utilities for writing Supply Chain Firewall configuration to supported files.
"""

from pathlib import Path
import pytest
from tempfile import NamedTemporaryFile

from scfw.configure.env import _BLOCK_END, _BLOCK_START
import scfw.configure.env as env
from scfw.constants import (
    DD_AGENT_PORT_VAR,
    DD_API_KEY_VAR,
    DD_API_LOGGER_ENABLED_VAR,
    DD_LOG_LEVEL_VAR,
    SCFW_HOME_VAR,
)

ORIGINAL_CONFIG = """\
# Set an environment variable
export MY_ENV_VAR=foo
"""

SCFW_CONFIG_BASE = """\
alias npm="scfw run npm"
alias pip="scfw run pip"
export SCFW_DD_AGENT_LOG_PORT="10365"
export DD_LOG_LEVEL="ALLOW"
"""

SCFW_CONFIG_UPDATED = """\
alias poetry="scfw run poetry"
export SCFW_HOME="~/.scfw"
"""


@pytest.mark.parametrize(
        "answers,expected",
        [
            # Empty answers produce empty config
            (
                {},
                "",
            ),
            # npm alias
            (
                {"alias_npm": True},
                'alias npm="scfw run npm"\n',
            ),
            # pip alias
            (
                {"alias_pip": True},
                'alias pip="scfw run pip"\n',
            ),
            # poetry alias
            (
                {"alias_poetry": True},
                'alias poetry="scfw run poetry"\n',
            ),
            # Datadog Agent port
            (
                {"dd_agent_port": "10365"},
                f'export {DD_AGENT_PORT_VAR}="10365"\n',
            ),
            # Datadog HTTP API logger enabled via dd_api_logger key
            (
                {"dd_api_logger": True},
                f'export {DD_API_LOGGER_ENABLED_VAR}="1"\n',
            ),
            # dd_api_logger=False produces no output
            (
                {"dd_api_logger": False},
                "",
            ),
            # Datadog API key
            (
                {"dd_api_key": "abc123"},
                f'export {DD_API_KEY_VAR}="abc123"\n',
            ),
            # Log level
            (
                {"dd_log_level": "ALLOW"},
                f'export {DD_LOG_LEVEL_VAR}="ALLOW"\n',
            ),
            # SCFW home directory
            (
                {"scfw_home": "~/.scfw"},
                f'export {SCFW_HOME_VAR}="~/.scfw"\n',
            ),
            # All options together, in emission order
            (
                {
                    "alias_npm": True,
                    "alias_pip": True,
                    "alias_poetry": True,
                    "dd_agent_port": "10365",
                    "dd_api_logger": True,
                    "dd_api_key": "abc123",
                    "dd_log_level": "BLOCK",
                    "scfw_home": "~/.scfw",
                },
                (
                    'alias npm="scfw run npm"\n'
                    'alias pip="scfw run pip"\n'
                    'alias poetry="scfw run poetry"\n'
                    f'export {DD_AGENT_PORT_VAR}="10365"\n'
                    f'export {DD_API_LOGGER_ENABLED_VAR}="1"\n'
                    f'export {DD_API_KEY_VAR}="abc123"\n'
                    f'export {DD_LOG_LEVEL_VAR}="BLOCK"\n'
                    f'export {SCFW_HOME_VAR}="~/.scfw"\n'
                ),
            ),
        ]
)
def test_format_answers(answers: dict, expected: str):
    """
    Test that configuration answers are formatted into the expected .rc file content.
    """
    assert env._format_answers(answers) == expected


def enclose(scfw_config: str) -> str:
    """
    Enclose the given `scfw_config` in its block comments.
    """
    return f"{_BLOCK_START}\n{scfw_config}{_BLOCK_END}"


@pytest.mark.parametrize(
        "original_config,scfw_config,updated_config",
        [
            # Initial configuration of an empty file
            (
                "",
                SCFW_CONFIG_BASE,
                f"\n{enclose(SCFW_CONFIG_BASE)}\n",
            ),
            # Initial configuration of a nonempty file
            (
                ORIGINAL_CONFIG,
                SCFW_CONFIG_BASE,
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_BASE)}\n",
            ),
            # Update configuration when there is no content inside the SCFW block
            (
                enclose(""),
                SCFW_CONFIG_UPDATED,
                enclose(SCFW_CONFIG_UPDATED),
            ),
            # Update configuration in an otherwise empty file with leading and
            # trailing whitespace (as would be added when we configure initially)
            (
                f"\n{enclose(SCFW_CONFIG_BASE)}\n",
                SCFW_CONFIG_UPDATED,
                f"\n{enclose(SCFW_CONFIG_UPDATED)}\n",
            ),
            # Update configuration in an otherwise empty file with no surrounding whitespace
            (
                enclose(SCFW_CONFIG_BASE),
                SCFW_CONFIG_UPDATED,
                enclose(SCFW_CONFIG_UPDATED),
            ),
            # Update configuration at the end of a nonempty file where the SCFW
            # configuration block is separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_BASE)}\n",
                SCFW_CONFIG_UPDATED,
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_UPDATED)}\n",
            ),
            # Update configuration at the end of a nonempty file where the SCFW
            # configuration block is not separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_BASE)}",
                SCFW_CONFIG_UPDATED,
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_UPDATED)}",
            ),
            # Update configuration in the middle of a nonempty file where the SCFW
            # configuration block is separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_BASE)}\n{ORIGINAL_CONFIG}",
                SCFW_CONFIG_UPDATED,
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_UPDATED)}\n{ORIGINAL_CONFIG}",
            ),
            # Update configuration in the middle of a nonempty file where the SCFW
            # configuration block is not separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_BASE)}{ORIGINAL_CONFIG}",
                SCFW_CONFIG_UPDATED,
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_UPDATED)}{ORIGINAL_CONFIG}",
            ),
            # Remove configuration from an empty file
            (
                "",
                "",
                "",
            ),
            # Remove configuration from a file that contains no configuration
            (
                ORIGINAL_CONFIG,
                "",
                ORIGINAL_CONFIG,
            ),
            # Remove configuration from an otherwise empty file with no leading or
            # trailing whitespace
            (
                enclose(SCFW_CONFIG_BASE),
                "",
                "",
            ),
            # Remove configuration from an otherwise empty file with leading and
            # trailing whitespace (as would be added when we configure initially)
            (
                f"\n{enclose(SCFW_CONFIG_BASE)}\n",
                "",
                "\n\n",
            ),
            # Remove configuration from the end of a nonempty file where the SCFW
            # configuration block is separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_BASE)}\n",
                "",
                f"{ORIGINAL_CONFIG}\n\n"
            ),
            # Remove configuration from the end of a nonempty file where the SCFW
            # configuration block is not separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_BASE)}",
                "",
                ORIGINAL_CONFIG,
            ),
            # Remove configuration from the middle of a nonempty file where the SCFW
            # configuation block is separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}\n{enclose(SCFW_CONFIG_BASE)}\n{ORIGINAL_CONFIG}",
                "",
                f"{ORIGINAL_CONFIG}\n\n{ORIGINAL_CONFIG}",
            ),
            # Remove configuration from the middle of a nonempty file where the SCFW
            # configuation block is not separated from surrounding content by whitespace
            (
                f"{ORIGINAL_CONFIG}{enclose(SCFW_CONFIG_BASE)}{ORIGINAL_CONFIG}",
                "",
                f"{ORIGINAL_CONFIG}{ORIGINAL_CONFIG}",
            ),
        ]
)
def test_config_file_update(original_config: str, scfw_config: str, updated_config: str):
    """
    Test that an update to configuration file contents has the expected result.
    """
    with NamedTemporaryFile(mode="r+") as f:
        if original_config:
            f.write(original_config)
            f.seek(0)

        env._update_config_file(Path(f.name), scfw_config)

        content = f.read()
        print(f"'{content}'")

        assert content == updated_config
