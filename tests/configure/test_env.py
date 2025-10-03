"""
Tests of utilities for writing Supply-Chain Firewall configuration to supported files.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile

from scfw.configure.env import _BLOCK_END, _BLOCK_START
import scfw.configure.env as env

ORIGINAL_CONFIG_1 = """\
# Add Rust environment
. "$HOME/.cargo/env"
"""

ORIGINAL_CONFIG_2 = """\
alias ..="cd .."
"""

SCFW_CONFIG_BASE = """\
alias npm="scfw run npm"
alias pip="scfw run pip"
export SCFW_DD_AGENT_LOG_PORT="10365"
export DD_LOG_LEVEL="ALLOW"
"""

SCFW_CONFIG_UPDATED = """\
alias npm="scfw run npm"
alias pip="scfw run pip"
alias poetry="scfw run poetry"
export SCFW_DD_AGENT_LOG_PORT="10365"
export DD_LOG_LEVEL="ALLOW"
"""


def test_add_initial_config_empty_file():
    """
    Test of initially adding the SCFW config to an empty file.
    """
    with NamedTemporaryFile(mode="r+") as f:
        env._update_config_file(Path(f.name), SCFW_CONFIG_BASE)

        content = f.read()
        print(f"'{content}'")

        assert content == (
            "\n"
            f"{_BLOCK_START}\n"
            f"{SCFW_CONFIG_BASE}"
            f"{_BLOCK_END}\n"
        )


def test_add_initial_config_nonempty_file():
    """
    Test of initially adding the SCFW config to a nonempty file.
    """
    with NamedTemporaryFile(mode="r+") as f:
        f.write(ORIGINAL_CONFIG_1)
        f.seek(0)

        env._update_config_file(Path(f.name), SCFW_CONFIG_BASE)

        content = f.read()
        print(f"'{content}'")

        assert content == (
            f"{ORIGINAL_CONFIG_1}"
            "\n"
            f"{_BLOCK_START}\n"
            f"{SCFW_CONFIG_BASE}"
            f"{_BLOCK_END}\n"
        )


def test_update_config_end_of_file():
    """
    Test of updating the SCFW config when it is at the end of the file.
    """
    with NamedTemporaryFile(mode="r+") as f:
        f.write(ORIGINAL_CONFIG_1)
        f.write(f"\n{_BLOCK_START}\n")
        f.write(SCFW_CONFIG_BASE)
        f.write(f"{_BLOCK_END}\n")
        f.seek(0)

        env._update_config_file(Path(f.name), SCFW_CONFIG_UPDATED)

        content = f.read()
        print(f"'{content}'")

        assert content == (
            f"{ORIGINAL_CONFIG_1}"
            "\n"
            f"{_BLOCK_START}\n"
            f"{SCFW_CONFIG_UPDATED}"
            f"{_BLOCK_END}\n"
        )


def test_update_config_middle_of_file():
    """
    Test of updating the SCFW config when it is in the middle of the file.
    """
    with NamedTemporaryFile(mode="r+") as f:
        f.write(ORIGINAL_CONFIG_1)
        f.write(f"\n{_BLOCK_START}\n")
        f.write(SCFW_CONFIG_BASE)
        f.write(f"{_BLOCK_END}\n")
        f.write(f"\n{ORIGINAL_CONFIG_2}")
        f.seek(0)

        env._update_config_file(Path(f.name), SCFW_CONFIG_UPDATED)

        content = f.read()
        print(f"'{content}'")

        assert content == (
            f"{ORIGINAL_CONFIG_1}"
            "\n"
            f"{_BLOCK_START}\n"
            f"{SCFW_CONFIG_UPDATED}"
            f"{_BLOCK_END}\n"
            f"\n{ORIGINAL_CONFIG_2}"
        )
