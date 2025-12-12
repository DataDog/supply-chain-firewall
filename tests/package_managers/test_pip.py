"""
Tests of pip's command line behavior.
"""

import json
import os
import subprocess
import sys
import tempfile

import packaging.version as version
import pytest

PIP_COMMAND_PREFIX = [sys.executable, "-m", "pip"]


def pip_list() -> str:
    """
    Get the current state of packages installed via pip.
    """
    pip_list_command = PIP_COMMAND_PREFIX + ["list", "--format", "freeze"]
    return subprocess.run(pip_list_command, check=True, text=True, capture_output=True).stdout.lower()


def select_test_install_target(installed_packages: str) -> str:
    """
    Select a test target that is not in the given installed packages output.

    This allows us to be certain when testing that nothing was installed in a dry-run.
    """
    def read_top_pypi_packages() -> set[str]:
        test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
        top_packages_file = os.path.join(test_dir, f"top_pypi_packages.txt")
        with open(top_packages_file) as f:
            return set(f.read().split())

    try:
        top_packages = read_top_pypi_packages()
        while (choice := top_packages.pop()) in installed_packages:
            pass
        return choice

    except KeyError:
        raise RuntimeError("Unable to select a target package for testing")


INIT_PIP_STATE = pip_list()
"""
Caches the pip installation state before running any tests.
"""

TEST_TARGET = select_test_install_target(INIT_PIP_STATE)
"""
A fresh (not currently installed) package target to use for testing.
"""


def test_pip_version_output():
    """
    Test that `pip --version` has the required format.
    """
    pip_version = subprocess.run(PIP_COMMAND_PREFIX + ["--version"], check=True, text=True, capture_output=True)
    version_str = pip_version.stdout.split()[1]
    version.parse(version_str)


@pytest.mark.parametrize(
        "command_line",
        [
            PIP_COMMAND_PREFIX + ["-h", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["--help", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "-h", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--help", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", TEST_TARGET, "--dry-run"]
        ]
)
def test_pip_no_change(command_line: list[str]):
    """
    Backend function for testing that a `pip` command does not encounter any
    errors and does not modify the local `pip` installation state.
    """
    subprocess.run(command_line, check=True)
    assert pip_list() == INIT_PIP_STATE


@pytest.mark.parametrize(
        "command_line",
        [
            PIP_COMMAND_PREFIX + ["--dry-run", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", "!!!a_nonexistent_p@ckage_name"]
        ]
)
def test_pip_no_change_error(command_line: list[str]):
    """
    Backend function for testing that a `pip` command raises an error and
    does not modify the local `pip` installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert pip_list() == INIT_PIP_STATE


@pytest.mark.parametrize(
        "should_fail,verbose_options",
        [
            (True,  ["-v"]),
            (False, ["-q"]),
            (True,  ["-v", "-q"]),
            (False, ["-v", "-qq"]),
            (True,  ["-vv", "-qq"]),
            (False, ["-vv", "-qqq"]),
            (True,  ["-vvv", "-qqq"]),
            (False, ["-vvv", "-qqqq"]),
            (True,  ["-vvvv", "-qqqq"]),
            (False, ["-vvvv", "-qqqqq"]),
        ]
)
def test_pip_install_report_verbose_json(should_fail: bool, verbose_options: list[str]):
    """
    Test to determine how many `-q/--quiet` options are needed to override various
    numbers of `-v/--verbose` options (no effect after three), measured by whether
    the report JSON parses successfully when read from stdout.
    """
    command_line = (
        PIP_COMMAND_PREFIX + ["install", "--dry-run", "--report", "-", TEST_TARGET] + verbose_options
    )
    p = subprocess.run(command_line, check=True, text=True, capture_output=True)
    if should_fail:
        with pytest.raises(json.JSONDecodeError):
            json.loads(p.stdout)
    else:
        json.loads(p.stdout)


def test_pip_install_report_override():
    """
    Test that all but the last instance of the `--report` option in the command
    line are ignored by `pip`.
    """
    with tempfile.NamedTemporaryFile() as tmpfile:
        command_line = (
            PIP_COMMAND_PREFIX +
            ["--quiet", "install", "--dry-run", "--report", tmpfile.name, TEST_TARGET, "--report", "-"]
        )
        p = subprocess.run(command_line, check=True, text=True, capture_output=True)
        # The report went to stdout and has installation targets
        assert p.stdout
        report = json.loads(p.stdout)
        assert report.get("install")
        # Nothing was written to the temporary file
        assert tmpfile.read() == b''
