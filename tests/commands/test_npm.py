import os
import pytest
import subprocess


def read_top_packages() -> set[str]:
    """
    Read the top npm packages from the included file.
    """
    test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
    top_packages_file = os.path.join(test_dir, "top_npm_packages.txt")
    with open(top_packages_file, 'r') as f:
        return set(f.read().split())


def npm_list() -> str:
    """
    Get the current state of the npm installation.
    """
    p = subprocess.run(["npm", "list"], check=True, text=True, capture_output=True)
    return p.stdout


def select_test_install_target(top_packages: set[str], npm_list: str) -> str:
    """
    Select a test target from `top_packages` that is not in the given `npm_list`
    output.

    This allows us to be certain when testing that nothing was installed in a
    dry-run.
    """
    try:
        while (choice := top_packages.pop()) in npm_list:
            pass
    except KeyError:
        # Pick something safe in the unlikely case that all top packages are
        # already installed
        choice = "lodash"
    
    return choice


INIT_NPM_STATE = npm_list()
TEST_TARGET = select_test_install_target(read_top_packages(), INIT_NPM_STATE)


def test_npm_help_short():
    """
    Test that nothing is installed when the short form help option is present.
    """
    command_line = ["npm", "-h", "install", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_help_long():
    """
    Test that nothing is installed when the long form help option is present.
    """
    command_line = ["npm", "--help", "install", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_dry_run():
    """
    Test that nothing is installed when the --dry-run option is present anywhere.
    """
    command_line_1 = ["npm", "--dry-run", "install", TEST_TARGET]
    command_line_2 = ["npm", "install", "--dry-run", TEST_TARGET]
    command_line_3 = ["npm", "install", TEST_TARGET, "--dry-run"]

    subprocess.run(command_line_1, check=True)
    assert npm_list() == INIT_NPM_STATE

    subprocess.run(command_line_2, check=True)
    assert npm_list() == INIT_NPM_STATE

    subprocess.run(command_line_3, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_dry_run_multiple():
    """
    Test that multiple instances of the --dry-run option may be given without
    causing an error.
    """
    command_line = ["npm", "--dry-run", "install", "--dry-run", TEST_TARGET, "--dry-run"]
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_incorrect_usage_error():
    """
    Test to show that in some cases of incorrect usage, npm will raise an error.
    """
    command_line = ["npm", "--non-existent-option"]
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE


def test_npm_incorrect_usage_no_error():
    """
    Test to show that in other cases of incorrect usage, npm will proceed anyway.
    """
    command_line = ["npm", "--non-existent-option", "install", TEST_TARGET, "--dry-run"]
    subprocess.run(command_line, check=True)
    assert npm_list() == INIT_NPM_STATE
