"""
Tests of npm's command line behavior.
"""

import packaging.version as version
import pytest
import subprocess

from scfw.ecosystem import ECOSYSTEM

from .utils import read_top_packages, select_test_install_target


def npm_list() -> str:
    """
    Get the current state of packages installed via npm.
    """
    return subprocess.run(["npm", "list", "--all"], check=True, text=True, capture_output=True).stdout.lower()


INIT_NPM_STATE = npm_list()
"""
Caches the npm installation state before running any tests.
"""

TEST_TARGET = select_test_install_target(read_top_packages(ECOSYSTEM.Npm), INIT_NPM_STATE)
"""
A fresh (not currently installed) package target to use for testing.
"""


def test_npm_version_output():
    """
    Test that `npm --version` has the required format.
    """
    version_str = subprocess.run(["npm", "--version"], check=True, text=True, capture_output=True)
    version.parse(version_str.stdout.strip())


@pytest.mark.parametrize(
        "command_line",
        [
            ["npm", "-h", "install", TEST_TARGET],
            ["npm", "--help", "install", TEST_TARGET],
            ["npm", "--dry-run", "install", TEST_TARGET],
            ["npm", "install", "--dry-run", TEST_TARGET],
            ["npm", "install", TEST_TARGET, "--dry-run"],
            ["npm", "--dry-run", "install", "--dry-run", TEST_TARGET, "--dry-run"],
            ["npm", "--non-existent-option", "install", TEST_TARGET, "--dry-run"]
        ]
)
def test_npm_no_change(command_line: list[str]):
    """
    Backend function for testing that an `npm` command does not encounter any
    errors and does not modify the local `npm` installation state.
    """
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


@pytest.mark.parametrize(
        "command_line",
        [
            ["npm", "--non-existent-option"],
            ["npm", "install", "--dry-run", "!!!a_nonexistent_p@ckage_name"]
        ]
)
def test_npm_no_change_error(command_line: list[str]):
    """
    Backend function for testing that an `npm` command raises an error and
    does not modify the local `npm` installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE
