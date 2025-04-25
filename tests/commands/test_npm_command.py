"""
Tests of `NpmCommand`.
"""

import pytest

from scfw.commands.npm_command import NpmCommand
from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget

from .test_npm import INIT_NPM_STATE, TEST_TARGET, npm_list


@pytest.mark.parametrize(
        "command_line,has_targets",
        [
            (["npm", "install", TEST_TARGET], True),
            (["npm", "-h", "install", TEST_TARGET], False),
            (["npm", "--help", "install", TEST_TARGET], False),
            (["npm", "install", "-h", TEST_TARGET], False),
            (["npm", "install", "--help", TEST_TARGET], False),
            (["npm", "--dry-run", "install", TEST_TARGET], False),
            (["npm", "install", "--dry-run", TEST_TARGET], False),
            (["npm", "--non-existent-option"], False)
        ]
)
def test_npm_command_would_install(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that an `NpmCommand.would_install` call either
    does or does not have install targets and does not modify the local npm
    installation state.
    """
    command = NpmCommand(command_line)
    targets = command.would_install()
    if has_targets:
        assert targets
    else:
        assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_exact():
    """
    Test that `NpmCommand.would_install` gives the right answer relative to an
    exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: InstallTarget(ECOSYSTEM.Npm, p[0], p[1]),
            [
                ("js-tokens", "4.0.0"),
                ("loose-envify", "1.4.0"),
                ("react", "18.3.1")
            ]
        )
    )

    command_line = ["npm", "install", "react@18.3.1"]
    command = NpmCommand(command_line)
    targets = command.would_install()
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)
