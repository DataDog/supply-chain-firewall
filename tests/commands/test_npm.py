import os
import pytest
import subprocess

from scfw.ecosystem import ECOSYSTEM

from .utils import list_installed_packages, read_top_packages, select_test_install_target

npm_list = lambda : list_installed_packages(ECOSYSTEM.NPM)

INIT_NPM_STATE = npm_list()
TEST_TARGET = select_test_install_target(read_top_packages("top_npm_packages.txt"), INIT_NPM_STATE, "lodash")


def _test_npm_command_no_change(command_line: list[str]):
    """
    Backend function for testing that an npm command does not encounter any
    errors and does not modify the local npm installation state.
    """
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def _test_npm_command_no_change_error(command_line: list[str]):
    """
    Backend function for testing that an npm command raises an error and
    does not modify the local npm installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_help_short():
    """
    Test that nothing is installed when the short form help option is present.
    """
    _test_npm_command_no_change(["npm", "-h", "install", TEST_TARGET])


def test_npm_help_long():
    """
    Test that nothing is installed when the long form help option is present.
    """
    _test_npm_command_no_change(["npm", "--help", "install", TEST_TARGET])


def test_npm_dry_run():
    """
    Test that nothing is installed when the --dry-run option is present anywhere.
    """
    _test_npm_command_no_change(["npm", "--dry-run", "install", TEST_TARGET])
    _test_npm_command_no_change(["npm", "install", "--dry-run", TEST_TARGET])
    _test_npm_command_no_change(["npm", "install", TEST_TARGET, "--dry-run"])


def test_npm_dry_run_multiple():
    """
    Test that multiple instances of the --dry-run option may be given without
    causing an error.
    """
    _test_npm_command_no_change(["npm", "--dry-run", "install", "--dry-run", TEST_TARGET, "--dry-run"])


def test_npm_incorrect_usage_error():
    """
    Test to show that in some cases of incorrect usage, npm will raise an error.
    """
    _test_npm_command_no_change_error(["npm", "--non-existent-option"])


def test_npm_incorrect_usage_no_error():
    """
    Test to show that in other cases of incorrect usage, npm will proceed anyway.
    """
    _test_npm_command_no_change(["npm", "--non-existent-option", "install", TEST_TARGET, "--dry-run"])


def test_npm_install_nonexistent_package():
    """
    Test that npm raises an error when a user requests to install a
    nonexistent package.
    """
    _test_npm_command_no_change_error(["npm", "install", "--dry-run", "!!!a_nonexistent_p@ckage_name"])
