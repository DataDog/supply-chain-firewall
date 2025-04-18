import packaging.version as version
import pytest
import subprocess

from .utils import list_installed_packages, read_top_packages, select_test_install_target

TOP_NPM_PACKAGES = "top_npm_packages.txt"

npm_list = lambda : list_installed_packages("npm")

INIT_NPM_STATE = npm_list()
TEST_TARGET = select_test_install_target(read_top_packages(TOP_NPM_PACKAGES), INIT_NPM_STATE)
if not TEST_TARGET:
    raise ValueError("Unable to select target npm package for testing")


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


def test_npm_loglevel_override():
    """
    Test that all but the last instance of `--loglevel` are ignored by `npm`.
    """
    command_line = [
        "npm", "--loglevel", "silent", "install", "--dry-run", TEST_TARGET, "--loglevel", "silly"
    ]
    p = subprocess.run(command_line, check=True, text=True, capture_output=True)
    assert p.stderr
    assert "silly" in p.stderr
