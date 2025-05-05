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
from typing import Optional

POETRY_V2 = version.parse("2.0.0")

TEST_PROJECT_NAME = "foo"

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
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME)

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_latest(target_latest):
    """
    Initialize a Poetry project with the latest version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, target_latest)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_previous(target_previous):
    """
    Initialize a Poetry project with the previous version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, target_previous)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def init_poetry_state(new_poetry_project):
    """
    Caches the Poetry installation state before running any tests.
    """
    return poetry_show(new_poetry_project)


@pytest.fixture
def poetry_version():
    """
    The version number of the active Poetry executable.
    """
    return _poetry_version()


def test_poetry_version_output():
    """
    Test that `poetry --version` has the required format and parses correctly.
    """
    assert _poetry_version() is not None


@pytest.mark.parametrize(
        "command, min_poetry_version",
        [
            (["poetry", "-V", "add", TARGET], None),
            (["poetry", "add", "-V", TARGET], None),
            (["poetry", "add", TARGET, "-V"], None),
            (["poetry", "--version", "add", TARGET], None),
            (["poetry", "add", "--version", TARGET], None),
            (["poetry", "add", TARGET, "--version"], None),
            (["poetry", "-h", "add", TARGET], None),
            (["poetry", "add", "-h", TARGET], None),
            (["poetry", "add", TARGET, "-h"], None),
            (["poetry", "--help", "add", TARGET], None),
            (["poetry", "add", "--help", TARGET], None),
            (["poetry", "add", TARGET, "--help"], None),
            (["poetry", "--dry-run", "add", TARGET], None),
            (["poetry", "add", "--dry-run", TARGET], None),
            (["poetry", "add", TARGET, "--dry-run"], None),
            (["poetry", "-V", "install"], None),
            (["poetry", "install", "-V"], None),
            (["poetry", "--version", "install"], None),
            (["poetry", "install", "--version"], None),
            (["poetry", "-h", "install"], None),
            (["poetry", "install", "-h"], None),
            (["poetry", "--help", "install"], None),
            (["poetry", "install", "--help"], None),
            (["poetry", "--dry-run", "install"], None),
            (["poetry", "install", "--dry-run"], None),
            (["poetry", "-V", "sync"], POETRY_V2),
            (["poetry", "sync", "-V"], POETRY_V2),
            (["poetry", "--version", "sync"], POETRY_V2),
            (["poetry", "sync", "--version"], POETRY_V2),
            (["poetry", "-h", "sync"], POETRY_V2),
            (["poetry", "sync", "-h"], POETRY_V2),
            (["poetry", "--help", "sync"], POETRY_V2),
            (["poetry", "sync", "--help"], POETRY_V2),
            (["poetry", "--dry-run", "sync"], POETRY_V2),
            (["poetry", "sync", "--dry-run"], POETRY_V2),
        ]
)
def test_poetry_no_change(poetry_version, new_poetry_project, init_poetry_state, command, min_poetry_version):
    """
    Tests that a Poetry command does not encounter any errors and does not
    modify the local installation state.
    """
    if min_poetry_version and poetry_version < min_poetry_version:
        return

    subprocess.run(command, check=True, cwd=new_poetry_project)
    assert poetry_show(new_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command, min_poetry_version",
        [
            (["poetry", "add", "!a_nonexistent_p@ckage_name"], None),
            (["poetry", "add", "--dry-run", "!a_nonexistent_p@ckage_name"], None),
            (["poetry", "add", "--nonexistent-option", TARGET], None),
            (["poetry", "add", "-G", TARGET], None),
            (["poetry", "add", "--group", TARGET], None),
            (["poetry", "add", "-E", TARGET], None),
            (["poetry", "add", "--extras", TARGET], None),
            (["poetry", "add", "--optional", TARGET], POETRY_V2),
            (["poetry", "add", "--python", TARGET], None),
            (["poetry", "add", "--platform", TARGET], None),
            (["poetry", "add", "--markers", TARGET], None),
            (["poetry", "add", "--source", TARGET], None),
            (["poetry", "add", "-P", TARGET], None),
            (["poetry", "add", "--project", TARGET], None),
            (["poetry", "add", "-C", TARGET], None),
            (["poetry", "add", "--directory", TARGET], None),
            (["poetry", "install", "unnecessary_argument"], None),
            (["poetry", "install", "--dry-run", "unnecessary_argument"], None),
            (["poetry", "install", "--nonexistent-option"], None),
            (["poetry", "install", "--without"], None),
            (["poetry", "install", "--with"], None),
            (["poetry", "install", "--only"], None),
            (["poetry", "install", "-E"], None),
            (["poetry", "install", "--extras"], None),
            (["poetry", "install", "-P"], None),
            (["poetry", "install", "--project"], None),
            (["poetry", "install", "-C"], None),
            (["poetry", "install", "--directory"], None),
            (["poetry", "sync", "unnecessary_argument"], POETRY_V2),
            (["poetry", "sync", "--dry-run", "unnecessary_argument"], POETRY_V2),
            (["poetry", "sync", "--nonexistent-option"], POETRY_V2),
            (["poetry", "sync", "--without"], POETRY_V2),
            (["poetry", "sync", "--with"], POETRY_V2),
            (["poetry", "sync", "--only"], POETRY_V2),
            (["poetry", "sync", "-E"], POETRY_V2),
            (["poetry", "sync", "--extras"], POETRY_V2),
            (["poetry", "sync", "-P"], POETRY_V2),
            (["poetry", "sync", "--project"], POETRY_V2),
            (["poetry", "sync", "-C"], POETRY_V2),
            (["poetry", "sync", "--directory"], POETRY_V2),
        ]
)
def test_poetry_error_no_change(poetry_version, new_poetry_project, init_poetry_state, command, min_poetry_version):
    """
    Tests that a Poetry command that encounters an error does not modify
    the local installation state.
    """
    if min_poetry_version and poetry_version < min_poetry_version:
        return

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command, check=True, cwd=new_poetry_project)
    assert poetry_show(new_poetry_project) == init_poetry_state


@pytest.mark.parametrize(
        "command, target, version, min_poetry_version",
        [
            (["poetry", "add", "--dry-run", TARGET], TARGET, "target_latest", None),
            (["poetry", "install", "--dry-run"], TEST_PROJECT_NAME, "0.1.0", None),
            (["poetry", "sync", "--dry-run"], TEST_PROJECT_NAME, "0.1.0", POETRY_V2),
        ]
)
def test_poetry_dry_run_output_install(
    poetry_version,
    new_poetry_project,
    target_latest,
    command,
    target,
    version,
    min_poetry_version
):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency installation has the expected format.
    """
    def is_install_line(target: str, version: str, line: str) -> bool:
        match = re.search(r"Installing (?:the current project: )?(.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and match.group(2) == version and "Skipped" not in line

    if min_poetry_version and poetry_version < min_poetry_version:
        return

    version = target_latest if version == "target_latest" else version

    dry_run = subprocess.run(command, check=True, cwd=new_poetry_project, text=True, capture_output=True)
    assert any(is_install_line(target, version, line) for line in dry_run.stdout.split('\n'))


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


def _poetry_version() -> Optional[version.Version]:
    """
    Get the version number of the active Poetry executable if it has the required
    format, otherwise return `None`.
    """
    try:
        poetry_version = subprocess.run(["poetry", "--version"], check=True, text=True, capture_output=True)
        match = re.search(r"Poetry \(version (.*)\)", poetry_version.stdout)
        return version.parse(match.group(1)) if match else None
    except Exception:
        return None


def _init_poetry_project(directory, name, dependencies = None):
    """
    Initialize a fresh Poetry project in `directory` with the given `dependencies`.
    """
    subprocess.run(["poetry", "init", "--no-interaction", "--name", name], check=True, cwd=directory)
    subprocess.run(["poetry", "lock"], check=True, cwd=directory)

    # Create a separate venv for Poetry to use during testing
    venv_path = Path(directory) / "venv"
    venv_python_path = venv_path / "bin" / "python"
    subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
    subprocess.run(["poetry", "env", "use", venv_python_path], check=True, cwd=directory)

    if dependencies:
        for package, version in dependencies:
            subprocess.run(["poetry", "add", f"{package}=={version}"], check=True, cwd=directory)
