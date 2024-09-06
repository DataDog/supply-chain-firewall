import json
import packaging.version as version
import pytest
import subprocess
import sys
import tempfile

from scfw.ecosystem import ECOSYSTEM

from .utils import list_installed_packages, read_top_packages, select_test_install_target

TOP_PIP_PACKAGES = "top_pip_packages.txt"

pip_list = lambda : list_installed_packages(ECOSYSTEM.PIP)

INIT_PIP_STATE = pip_list()
TEST_TARGET = select_test_install_target(read_top_packages(TOP_PIP_PACKAGES), INIT_PIP_STATE)
if not TEST_TARGET:
    raise ValueError("Unable to select target pip package for testing")

PIP_COMMAND_PREFIX = [sys.executable, "-m", "pip"]


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
