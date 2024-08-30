import os
import pytest
import subprocess

from scfw.ecosystem import ECOSYSTEM

from .utils import list_installed_packages, read_top_packages, select_test_install_target

npm_list = lambda : list_installed_packages(ECOSYSTEM.NPM)

INIT_NPM_STATE = npm_list()
TOP_NPM_PACKAGES = "top_npm_packages.txt"
TEST_TARGET = select_test_install_target(read_top_packages(TOP_NPM_PACKAGES), INIT_NPM_STATE, "lodash")


print(f"DEBUG: Initial npm state:\n{INIT_NPM_STATE}")
print(f"DEBUG: Test target: {TEST_TARGET}")


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
def test_npm_command_no_change(command_line: list[str]):
    """
    Backend function for testing that an npm command does not encounter any
    errors and does not modify the local npm installation state.
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
def test_npm_command_no_change_error(command_line: list[str]):
    """
    Backend function for testing that an npm command raises an error and
    does not modify the local npm installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE
