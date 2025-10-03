"""
Tests of utilities for writing Supply-Chain Firewall configuration to supported files.
"""

from pathlib import Path
import pytest
from tempfile import NamedTemporaryFile

from scfw.configure.env import _BLOCK_END, _BLOCK_START
import scfw.configure.env as env

ORIGINAL_CONFIG = """\
# Add Rust environment
. "$HOME/.cargo/env"
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
