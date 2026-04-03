"""
Provides a collection of common fixtures for the bun tests.
"""

import shutil
import subprocess
from pathlib import Path
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
def bun_project_dependency_latest_lockfile():
    """
    Initialize a bun project with `TEST_PACKAGE@TEST_PACKAGE_LATEST` added
    as a dependency and covered in the lockfile but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
        with_lockfile=True,
        with_node_modules=False,
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


@pytest.fixture
def bun_project_dependency_previous():
    """
    Initialize a bun project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` added
    as a dependency but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def bun_project_dependency_previous_lockfile():
    """
    Initialize a bun project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` added
    as a dependency and covered in the lockfile but not installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
        with_node_modules=False,
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def bun_project_installed_previous():
    """
    Initialize a bun project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_bun_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()


def init_bun_project(
    path: Path,
    dependencies: Optional[list[tuple[str, str]]] = None,
    with_lockfile: bool = False,
    with_node_modules: bool = False,
):
    """
    Initialize a bun project in `path` with the given `dependencies` and with or
    without the lockfile and node_modules directories present.

    Bun may create either `bun.lockb` or `bun.lock` depending on version and
    configuration, so both are treated as valid lockfile names.
    """
    subprocess.run(
        ["bun", "init", "-y"], check=True, text=True, capture_output=True, cwd=path
    )

    if dependencies:
        for package, version in dependencies:
            subprocess.run(
                ["bun", "add", f"{package}@{version}"],
                check=True,
                text=True,
                capture_output=True,
                cwd=path,
            )

    _ensure_bun_install_state(
        path, with_lockfile=with_lockfile, with_node_modules=with_node_modules
    )


def _ensure_bun_install_state(
    path: Path,
    with_lockfile: bool,
    with_node_modules: bool,
):
    """
    Normalize bun install artifacts to match the requested fixture state.
    """
    if not with_lockfile:
        _remove_bun_lockfiles(path)

    if not with_node_modules:
        shutil.rmtree(path / "node_modules", ignore_errors=True)


def _remove_bun_lockfiles(path: Path):
    """
    Remove any bun lockfile format currently produced by the local bun version.
    """
    for lockfile_name in ("bun.lock", "bun.lockb"):
        lockfile_path = path / lockfile_name
        if lockfile_path.exists():
            lockfile_path.unlink()
