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

LOCAL_PACKAGE_NAME = "foo-local-test-package"
LOCAL_PACKAGE_VERSION = "1.0.0"

TEST_PACKAGE = "react"
TEST_PACKAGE_LATEST = "18.3.0"
TEST_PACKAGE_PREVIOUS = "18.2.0"

TEST_PACKAGE_LATEST_SPEC = f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"
TEST_PACKAGE_PREVIOUS_SPEC = f"{TEST_PACKAGE}@{TEST_PACKAGE_PREVIOUS}"

TEST_PACKAGE_LATEST_DEPENDENCIES = {
    (TEST_PACKAGE, TEST_PACKAGE_LATEST),
    ("js-tokens", "4.0.0"),
    ("loose-envify", "1.4.0"),
}
"""
Known dependencies of `TEST_PACKAGE@TEST_PACKAGE_LATEST`.
"""

TEST_PACKAGE_PREVIOUS_DEPENDENCIES = {
    (TEST_PACKAGE, TEST_PACKAGE_PREVIOUS),
    ("js-tokens", "4.0.0"),
    ("loose-envify", "1.4.0"),
}
"""
Known dependencies of `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS`.
"""


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


@pytest.fixture
def npm_project_local_dependency():
    """
    Initialize an npm project with a dependency on a local package.
    """
    local_package_tempdir = TemporaryDirectory()
    local_package_path = Path(local_package_tempdir.name) / LOCAL_PACKAGE_NAME
    os.mkdir(local_package_path)
    init_npm_project(local_package_path)

    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[local_package_path],
    )

    yield tempdir_path

    tempdir.cleanup()
    local_package_tempdir.cleanup()


@pytest.fixture
def npm_project_local_dependency_lockfile():
    """
    Initialize an npm project with a dependency on a local package (sourced from
    a local directory) covered in the lockfile but not installed.
    """
    local_package_tempdir = TemporaryDirectory()
    local_package_path = Path(local_package_tempdir.name) / LOCAL_PACKAGE_NAME
    os.mkdir(local_package_path)
    init_npm_project(local_package_path)

    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[local_package_path],
        with_lockfile=True,
    )

    yield tempdir_path

    tempdir.cleanup()
    local_package_tempdir.cleanup()


@pytest.fixture
def npm_project_local_dependency_installed():
    """
    Initialize an npm project with a dependency on a package installed from a
    local directory.
    """
    local_package_tempdir = TemporaryDirectory()
    local_package_path = Path(local_package_tempdir.name) / LOCAL_PACKAGE_NAME
    os.mkdir(local_package_path)
    init_npm_project(local_package_path)

    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    init_npm_project(
        tempdir_path,
        dependencies=[local_package_path],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()
    local_package_tempdir.cleanup()


def init_npm_project(
    path: Path,
    dependencies: Optional[list[tuple[str, str] | Path]] = None,
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

    for dependency in dependencies:
        # Dependency sourced from npm
        if isinstance(dependency, tuple) and len(dependency) == 2:
            package, version = dependency
            target_spec = f"{package}@{version}"
        # Dependency sourced from local directory
        elif isinstance(dependency, Path):
            target_spec = f"{dependency}"
        else:
            raise ValueError(f"Invalid test dependency specification: {dependency}")

        subprocess.run(
            ["npm", "install", "--save-exact", target_spec],
            check=True,
            text=True,
            capture_output=True,
            cwd=path,
        )

    if not (with_node_modules and with_lockfile):
        shutil.rmtree(path / "node_modules")

    if not with_lockfile:
        os.remove(path / "package-lock.json")
