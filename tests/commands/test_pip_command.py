"""
Tests of `PipCommand`.
"""

import shutil
import sys

import pytest

from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list


def test_executable():
    """
    Test whether `PipCommand` correctly discovers the Python executable active
    in the current environment.
    """
    python = shutil.which("python")
    command = PipCommand(["pip", "--version"])
    assert python and command.executable() == python


@pytest.mark.parametrize(
        "command_line,has_targets",
        [
            (["pip", "install", TEST_TARGET], True),
            (["pip", "-h", "install", TEST_TARGET], False),
            (["pip", "--help", "install", TEST_TARGET], False),
            (["pip", "install", "-h", TEST_TARGET], False),
            (["pip", "install", "--help", TEST_TARGET], False),
            (["pip", "install" "--dry-run", TEST_TARGET], False),
            (["pip", "--dry-run", "install", TEST_TARGET], False),
            (["pip", "install", "--report", "report.json", TEST_TARGET], True),
            (["pip", "install", "--non-existent-option", TEST_TARGET], False)
        ]
)
def test_pip_command_would_install(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that a `PipCommand.would_install` call either
    does or does not have install targets and does not modify the local pip
    installation state.
    """
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    if has_targets:
        assert targets
    else:
        assert not targets
    assert pip_list() == INIT_PIP_STATE


def test_pip_command_would_install_exact():
    """
    Test that `PipCommand.would_install` gives the right answer relative to an
    exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: Package(ECOSYSTEM.PyPI, p[0], p[1]),
            [
                ("botocore", "1.15.0"),
                ("docutils", "0.15.2"),
                ("jmespath", "0.10.0"),
                ("python-dateutil", "2.9.0.post0"),
                ("six", "1.17.0"),
                ("urllib3", "1.25.11")
            ]
        )
    )

    command_line = ["pip", "install", "--ignore-installed", "botocore==1.15.0"]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)
