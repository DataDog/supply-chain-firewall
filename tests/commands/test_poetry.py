"""
Tests of Poetry's command line behavior.
"""

import packaging.version as version
from pathlib import Path
import pytest
import re
import requests
import subprocess
import sys
from tempfile import TemporaryDirectory

# Tree-sitter is a convenient test target because it never has any dependencies
# and is not part of the standard set of system Python modules
TARGET = "tree-sitter"


@pytest.fixture
def target_releases():
    """
    Caches the list version numbers of available `TARGET` releases on PyPI.
    """
    r = requests.get(f"https://pypi.org/pypi/{TARGET}/json", timeout=5)
    r.raise_for_status()
    return list(r.json()["releases"])


@pytest.fixture
def target_latest(target_releases):
    """
    Return the version number for the latest `TARGET` release.
    """
    # SAFETY: This is guaranteed to exist as long as Tree-sitter does
    return target_releases[-1]


@pytest.fixture
def target_previous(target_releases):
    """
    Return the version number for the previous `TARGET` release.
    """
    # SAFETY: This is guaranteed to exist as long as Tree-sitter does
    return target_releases[-2]


@pytest.fixture
def new_poetry_project():
    """
    Initialize a clean Poetry project for use in testing.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name)

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_latest(target_latest):
    """
    Initialize a Poetry project with the latest version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, [(TARGET, target_latest)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_previous(target_previous):
    """
    Initialize a Poetry project with the previous version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, [(TARGET, target_previous)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def init_poetry_state(new_poetry_project):
    """
    Caches the Poetry installation state before running any tests.
    """
    return poetry_show(new_poetry_project)


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
            ["poetry", "-V", "add", TARGET],
            ["poetry", "add", "-V", TARGET],
            ["poetry", "add", TARGET, "-V"],
            ["poetry", "--version", "add", TARGET],
            ["poetry", "add", "--version", TARGET],
            ["poetry", "add", TARGET, "--version"],
            ["poetry", "-h", "add", TARGET],
            ["poetry", "add", "-h", TARGET],
            ["poetry", "add", TARGET, "-h"],
            ["poetry", "--help", "add", TARGET],
            ["poetry", "add", "--help", TARGET],
            ["poetry", "add", TARGET, "--help"],
            ["poetry", "--dry-run", "add", TARGET],
            ["poetry", "add", "--dry-run", TARGET],
            ["poetry", "add", TARGET, "--dry-run"],
        ]
)
def test_poetry_no_change(new_poetry_project, init_poetry_state, command):
    """
    Tests that a Poetry command does not encounter any errors and does not
    modify the local installation state.
    """
    subprocess.run(command, check=True, cwd=new_poetry_project)
    assert poetry_show(new_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command",
        [
            ["poetry", "add", "!a_nonexistent_p@ckage_name"],
            ["poetry", "add", "--dry-run", "!a_nonexistent_p@ckage_name"],
            ["poetry", "add", "--nonexistent-option", TARGET],
            ["poetry", "add", "-G", TARGET],
            ["poetry", "add", "--group", TARGET],
            ["poetry", "add", "-E", TARGET],
            ["poetry", "add", "--extras", TARGET],
            ["poetry", "add", "--python", TARGET],
            ["poetry", "add", "--platform", TARGET],
            ["poetry", "add", "--markers", TARGET],
            ["poetry", "add", "--source", TARGET],
            ["poetry", "add", "-P", TARGET],
            ["poetry", "add", "--project", TARGET],
            ["poetry", "add", "-C", TARGET],
            ["poetry", "add", "--directory", TARGET],
        ]
)
def test_poetry_error_no_change(new_poetry_project, init_poetry_state, command):
    """
    Tests that a Poetry command that encounters an error does not modify
    the local installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command, check=True, cwd=new_poetry_project)
    assert poetry_show(new_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command",
        [
            ["poetry", "add", "--dry-run", TARGET],
        ]
)
def test_poetry_dry_run_output_install(new_poetry_project, command):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency installation has the expected format.
    """
    def is_install_line(target: str, line: str) -> bool:
        match = re.search(r"Installing (.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and "Skipped" not in line

    dry_run = subprocess.run(command, check=True, cwd=new_poetry_project, text=True, capture_output=True)
    assert any(is_install_line(TARGET, line) for line in dry_run.stdout.split('\n'))


def test_poetry_dry_run_output_update(poetry_project_target_previous, target_latest):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency update has the expected format.
    """
    def is_update_line(target: str, line: str) -> bool:
        match = re.search(r"Updating (.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and "Skipped" not in line

    dry_run = subprocess.run(
        ["poetry", "add", "--dry-run", f"{TARGET}=={target_latest}"],
        check=True,
        cwd=poetry_project_target_previous,
        text=True,
        capture_output=True
    )
    assert any(is_update_line(TARGET, line) for line in dry_run.stdout.split('\n'))


def test_poetry_dry_run_output_downgrade(poetry_project_target_latest, target_previous):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency downgrade has the expected format.
    """
    def is_downgrade_line(target: str, line: str) -> bool:
        match = re.search(r"(Updating|Downgrading) (.*) \((.*)\)", line.strip())
        return match is not None and match.group(2) == target and "Skipped" not in line

    dry_run = subprocess.run(
        ["poetry", "add", "--dry-run", f"{TARGET}=={target_previous}"],
        check=True,
        cwd=poetry_project_target_latest,
        text=True,
        capture_output=True
    )
    assert any(is_downgrade_line(TARGET, line) for line in dry_run.stdout.split('\n'))


def poetry_show(project_dir: str) -> str:
    """
    Get the current state of packages installed via Poetry.
    """
    poetry_show = subprocess.run(["poetry", "show"], check=True, cwd=project_dir, text=True, capture_output=True)
    return poetry_show.stdout.lower()


def _init_poetry_project(directory, dependencies = None):
    """
    Initialize a fresh Poetry project in `directory` with the given `dependencies`.
    """
    subprocess.run(["poetry", "init", "--no-interaction", "--name", "foo"], check=True, cwd=directory)
    subprocess.run(["poetry", "lock"], check=True, cwd=directory)

    # Create a separate venv for Poetry to use during testing
    venv_path = Path(directory) / "venv"
    venv_python_path = venv_path / "bin" / "python"
    subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
    subprocess.run(["poetry", "env", "use", venv_python_path], check=True, cwd=directory)

    if dependencies:
        for package, version in dependencies:
            subprocess.run(["poetry", "add", f"{package}=={version}"], check=True, cwd=directory)
