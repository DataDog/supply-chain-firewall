import json
import os
import pytest
import subprocess
import sys
import tempfile


def read_top_packages() -> set[str]:
    """
    Read the top pip packages from the included file.
    """
    test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
    top_packages_file = os.path.join(test_dir, "top_pip_packages.txt")
    with open(top_packages_file) as f:
        return set(f.read().split())


def pip_list(executable: str) -> str:
    """
    Get the current state of the pip installation relative to the given
    Python executable.
    """
    p = subprocess.run([executable, "-m", "pip", "list"], check=True, text=True, capture_output=True)
    return p.stdout


def select_test_install_target(top_packages: set[str], pip_list: str) -> str:
    """
    Select a test target from `top_packages` that is not in the given `pip_list`
    output.

    This allows us to be certain when testing that nothing was installed in a
    dry-run.
    """
    try:
        while (choice := top_packages.pop()) in pip_list:
            pass
    except KeyError:
        # Pick something safe in the unlikely case that all top packages are
        # already installed
        choice = "requests"

    return choice


INIT_PIP_STATE = pip_list(sys.executable)
TEST_TARGET = select_test_install_target(read_top_packages(), INIT_PIP_STATE)


def test_pip_help_short():
    """
    Test that nothing is installed when the short form help option is present
    and attached to the pip command itself.
    """
    command_line = [sys.executable, "-m", "pip", "-h", "install", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_help_long():
    """
    Test that nothing is installed when the long form help option is present
    and attached to the pip command itself.
    """
    command_line = [sys.executable, "-m", "pip", "--help", "install", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_help_short():
    """
    Test that nothing is installed when the short form help option is present
    and attached to the pip install subcommand.
    """
    command_line = [sys.executable, "-m", "pip", "install", "-h", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_help_long():
    """
    Test that nothing is installed when the long form help option is present
    and attached to the pip install subcommand.
    """
    command_line = [sys.executable, "-m", "pip", "install", "--help", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_dry_run_correct():
    """
    Test that nothing is installed when the pip install `--dry-run` option is
    used correctly.
    """
    command_line = [sys.executable, "-m", "pip", "install", "--dry-run", TEST_TARGET]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_dry_run_incorrect():
    """
    Test that an error occurs and that nothing is installed when the pip install
    `--dry-run` option is used incorrectly.
    """
    command_line = [sys.executable, "-m", "pip", "--dry-run", "install", TEST_TARGET]
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_dry_run_multiple():
    """
    Test that multiple correct instances of the pip install `--dry-run` option
    may be given without causing an error.
    """
    command_line = [sys.executable, "-m", "pip", "install", "--dry-run", TEST_TARGET, "--dry-run"]
    subprocess.run(command_line, check=True)
    assert pip_list(sys.executable) == INIT_PIP_STATE


def test_pip_install_report_multiple():
    """
    Test that all but the last instance of the `--report` option in the command
    line are ignored by pip.
    """
    with tempfile.NamedTemporaryFile() as tmpfile:
        command_line = [
            sys.executable, "-m",
            "pip", "--quiet", "install", "--dry-run", "--report", tmpfile.name, TEST_TARGET, "--report", "-"
        ]
        p = subprocess.run(command_line, check=True, text=True, capture_output=True)
        # The report went to stdout and has installation targets
        assert p.stdout
        report = json.loads(p.stdout)
        assert report.get("install")
        # Nothing was written to the temporary file
        assert tmpfile.read() == b''
