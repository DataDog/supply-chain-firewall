import sys

import pytest

from scfw.commands.pip_command import PipCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list


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
            lambda p: InstallTarget(ECOSYSTEM.PIP, p[0], p[1]),
            [
                ("certifi", "2024.8.30"),
                ("charset-normalizer", "3.3.2"),
                ("idna", "3.10"),
                ("requests", "2.32.3"),
                ("urllib3", "2.2.3")
            ]
        )
    )

    command_line = ["pip", "install", "--ignore-installed", "requests==2.32.3"]
    command = PipCommand(command_line, executable=sys.executable)
    targets = command.would_install()
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)
