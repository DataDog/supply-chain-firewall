"""
Provides a collection of common fixtures for the Poetry tests.
"""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

import pytest
import requests

TEST_PROJECT_NAME = "foo"

# Tree-sitter is a convenient test target because it never has any dependencies
# and is not part of the standard set of system Python modules
TARGET = "tree-sitter"

# Version numbers of available Tree-sitter releases on PyPI
TARGET_RELEASES = list(
    requests.get(f"https://pypi.org/pypi/{TARGET}/json", timeout=5).json()["releases"]
)

# The latest and most recent previous versions of Tree-sitter
TARGET_LATEST = TARGET_RELEASES[-1]
TARGET_PREVIOUS = TARGET_RELEASES[-2]


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
def poetry_project_target_latest():
    """
    Initialize a Poetry project with the latest version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, TARGET_LATEST)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_previous():
    """
    Initialize a Poetry project with the previous version of `TARGET` as a dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, TARGET_PREVIOUS)])

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_latest_lock_previous():
    """
    Initialize a Poetry project where the latest version of `TARGET` has been installed but
    the previous version of it is an as-yet uninstalled dependency of the project.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, TARGET_LATEST)])
    subprocess.run(["poetry", "add", "--lock", f"{TARGET}=={TARGET_PREVIOUS}"], check=True, cwd=tempdir.name)

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_target_previous_lock_latest():
    """
    Initialize a Poetry project where the previous version of `TARGET` has been installed but
    the latest version of it is an as-yet uninstalled dependency of the project.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME, [(TARGET, TARGET_PREVIOUS)])
    subprocess.run(["poetry", "add", "--lock", f"{TARGET}=={TARGET_LATEST}"], check=True, cwd=tempdir.name)

    yield tempdir.name

    tempdir.cleanup()


@pytest.fixture
def poetry_project_lock_latest():
    """
    Initialize a Poetry project where the latest version of `TARGET` is an as-yet
    uninstalled dependency.
    """
    tempdir = TemporaryDirectory()
    _init_poetry_project(tempdir.name, TEST_PROJECT_NAME)
    subprocess.run(["poetry", "add", "--lock", f"{TARGET}=={TARGET_LATEST}"], check=True, cwd=tempdir.name)

    yield tempdir.name

    tempdir.cleanup()


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
