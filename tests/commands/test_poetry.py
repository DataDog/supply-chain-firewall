"""
Tests of Poetry's command line behavior.
"""

import packaging.version as version
import pytest
import re
import subprocess
from tempfile import TemporaryDirectory

from scfw.ecosystem import ECOSYSTEM

from .utils import read_top_packages, select_test_install_target


@pytest.fixture
def test_poetry_project():
    """
    Initialize a clean Poetry project for use in testing.
    """
    tempdir = TemporaryDirectory()

    poetry_init_command = ["poetry", "init", "--no-interaction", "--name", "foo", "--python", ">=3.10,<4"]
    subprocess.run(poetry_init_command, check=True, cwd=tempdir.name)
    subprocess.run(["poetry", "lock"], check=True, cwd=tempdir.name)

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def init_poetry_state(test_poetry_project):
    """
    Caches the Poetry installation state before running any tests.
    """
    return poetry_show(test_poetry_project)


@pytest.fixture
def test_target(init_poetry_state):
    """
    A fresh (not currently installed) package target to use for testing.
    """
    return select_test_install_target(read_top_packages(ECOSYSTEM.PyPI), init_poetry_state)


def test_poetry_version_output():
    """
    Test that `poetry --version` has the required format.
    """
    poetry_version = subprocess.run(["poetry", "--version"], check=True, text=True, capture_output=True)
    match = re.search(r"Poetry \(version (.*)\)", poetry_version.stdout)
    assert match is not None
    version.parse(match.group(1))


@pytest.mark.parametrize(
        "command",
        [
            ["poetry", "-V", "add", "test_target"],
            ["poetry", "add", "-V", "test_target"],
            ["poetry", "add", "test_target", "-V"],
            ["poetry", "--version", "add", "test_target"],
            ["poetry", "add", "--version", "test_target"],
            ["poetry", "add", "test_target", "--version"],
            ["poetry", "-h", "add", "test_target"],
            ["poetry", "add", "-h", "test_target"],
            ["poetry", "add", "test_target", "-h"],
            ["poetry", "--help", "add", "test_target"],
            ["poetry", "add", "--help", "test_target"],
            ["poetry", "add", "test_target", "--help"],
            ["poetry", "--dry-run", "add", "test_target"],
            ["poetry", "add", "--dry-run", "test_target"],
            ["poetry", "add", "test_target", "--dry-run"],
        ]
)
def test_poetry_no_change(test_poetry_project, init_poetry_state, test_target, command):
    """
    Tests that a Poetry command does not encounter any errors and does not
    modify the local installation state.
    """
    command = [test_target if token == "test_target" else token for token in command]
    subprocess.run(command, check=True, cwd=test_poetry_project)
    assert poetry_show(test_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command",
        [
            ["poetry", "add", "!a_nonexistent_p@ckage_name"],
            ["poetry", "add", "--dry-run", "!a_nonexistent_p@ckage_name"],
            ["poetry", "add", "--nonexistent-option", "test_target"],
            ["poetry", "add", "-G", "test_target"],
            ["poetry", "add", "--group", "test_target"],
            ["poetry", "add", "-E", "test_target"],
            ["poetry", "add", "--extras", "test_target"],
            ["poetry", "add", "--python", "test_target"],
            ["poetry", "add", "--platform", "test_target"],
            ["poetry", "add", "--markers", "test_target"],
            ["poetry", "add", "--source", "test_target"],
            ["poetry", "add", "-P", "test_target"],
            ["poetry", "add", "--project", "test_target"],
            ["poetry", "add", "-C", "test_target"],
            ["poetry", "add", "--directory", "test_target"],
        ]
)
def test_poetry_error_no_change(test_poetry_project, init_poetry_state, test_target, command):
    """
    Tests that a Poetry command that encounters an error does not modify
    the local installation state.
    """
    command = [test_target if token == "test_target" else token for token in command]
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command, check=True, cwd=test_poetry_project)
    assert poetry_show(test_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command",
        [
            ["poetry", "add", "--dry-run", "test_target"],
        ]
)
def test_poetry_dry_run_output(test_poetry_project, test_target, command):
    """
    Tests that a dry-run of an installish Poetry command has the expected format.
    """
    def is_install_line(target: str, line: str) -> bool:
        match = re.search(r"Installing (.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and "Skipped" not in line

    command = [test_target if token == "test_target" else token for token in command]
    dry_run = subprocess.run(command, check=True, cwd=test_poetry_project, text=True, capture_output=True)
    assert any(is_install_line(test_target, line) for line in dry_run.stdout.split('\n'))


def poetry_show(project_dir: str) -> str:
    """
    Get the current state of packages installed via Poetry.
    """
    poetry_show = subprocess.run(["poetry", "show"], check=True, cwd=project_dir, text=True, capture_output=True)
    return poetry_show.stdout.lower()
