"""
Provides a collection of common fixtures for the bun tests.
"""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Optional

import pytest

TEST_PACKAGE = "react"
TEST_PACKAGE_LATEST = "19.2.4"
TEST_PACKAGE_PREVIOUS = "18.3.0"


@pytest.fixture
def new_bun_project():
    """
    Initialize a new bun project with no dependencies.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(tempdir_path)

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def bun_project_dependency_latest():
    """
    Initialize a bun project with the `TEST_PACKAGE@TEST_PACKAGE_LATEST` added
    as a dependency but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def bun_project_installed_latest():
    """
    Initialize a bun project with `TEST_PACKAGE@TEST_PACKAGE_LATEST` installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()


def init_bun_project(
    path: Path,
    dependencies: Optional[list[tuple[str, str]]] = None,
    with_lockfile: bool = True,
    with_node_modules: bool = True,
):
    """
    Initialize a bun project in `path` with the given `dependencies` and with or
    without the lockfile and node_modules directories present.
    """
    subprocess.run(["bun", "init", "-y"], check=True, text=True, capture_output=True, cwd=path)

    if not dependencies:
        return

    for package, version in dependencies:
        subprocess.run(
            ["bun", "add", f"{package}@{version}"],
            check=True,
            text=True,
            capture_output=True,
            cwd=path,
        )
