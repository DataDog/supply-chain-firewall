"""
Provides a collection of common fixtures for the npm tests.
"""

import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Optional

import pytest

TEST_PACKAGE = "react"
TEST_PACKAGE_LATEST = "18.3.0"
TEST_PACKAGE_PREVIOUS = "18.2.0"

TEST_PACKAGE_LATEST_SPEC = f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"
TEST_PACKAGE_PREVIOUS_SPEC = f"{TEST_PACKAGE}@{TEST_PACKAGE_PREVIOUS}"


@pytest.fixture
def empty_directory():
    """
    Initialize an empty directory.
    """
    tempdir = TemporaryDirectory()

    yield Path(tempdir.name)

    tempdir.cleanup()


@pytest.fixture
def new_npm_project():
    """
    Initialize a new npm project with no dependencies.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(tempdir_path)

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_dependency_latest():
    """
    Initialize an npm project with the `TEST_PACKAGE@TEST_PACKAGE_LATEST` added
    as a dependency but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_dependency_latest_lockfile():
    """
    Initialize an npm project with `TEST_PACKAGE@TEST_PACKAGE_LATEST` added
    as a dependency and covered in the lockfile but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
        with_lockfile=True,
        with_node_modules=False,
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_installed_latest():
    """
    Initialize an npm project with `TEST_PACKAGE@TEST_PACKAGE_LATEST` installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_dependency_previous():
    """
    Initialize an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` added
    as a dependency but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_dependency_previous_lockfile():
    """
    Initialize an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` added
    as a dependency and covered in the lockfile but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_installed_previous():
    """
    Initialize an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()


def init_npm_project(
    path: Path,
    dependencies: Optional[list[tuple[str, str]]] = None,
    with_lockfile: bool = False,
    with_node_modules: bool = False,
):
    """
    Initialize an npm project in `path` with the given `dependencies` and with or
    without the `package-lock.json` file and `node_modules/` directory present.

    Note that setting `with_lockfile=False` always results in the `node_modules/`
    directory being deleted, regardless of the value of `with_node_modules`.
    """
    subprocess.run(["npm", "init", "--yes"], check=True, text=True, capture_output=True, cwd=path)

    if not dependencies:
        return

    for package, version in dependencies:
        subprocess.run(
            ["npm", "install", "--save-exact", f"{package}@{version}"],
            check=True,
            text=True,
            capture_output=True,
            cwd=path,
        )

    if not (with_node_modules and with_lockfile):
        shutil.rmtree(path / "node_modules")

    if not with_lockfile:
        os.remove(path / "package-lock.json")
