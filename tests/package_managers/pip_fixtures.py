"""
Provides a collection of common fixtures for the pip tests.
"""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Optional

import pytest

TEST_PACKAGE_NAME = "foo"
TEST_PACKAGE_VERSION = "0.1.0"

REMOTE_PACKAGE_NAME = "tree-sitter"
REMOTE_PACKAGE_VERSION = "0.23.2"

LOCAL_PACKAGE_NAME = "bar"
LOCAL_PACKAGE_VERSION = "1.0.0"


@pytest.fixture
def new_pip_project():
    """
    Initialize a new `pip` project.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(tempdir_path, TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION)

    tempdir.cleanup()


@pytest.fixture
def new_pip_project_installed():
    """
    Initialize and install a new `pip` project.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(tempdir_path, TEST_PACKAGE_NAME, TEST_PACKAGE_VERSION, installed=True)

    tempdir.cleanup()


@pytest.fixture
def pip_project_remote_dependency():
    """
    Initialize a new `pip` project with a remote dependency from PyPI.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(
        tempdir_path,
        TEST_PACKAGE_NAME,
        TEST_PACKAGE_VERSION,
        dependencies=[(REMOTE_PACKAGE_NAME, REMOTE_PACKAGE_VERSION)],
    )

    tempdir.cleanup()


@pytest.fixture
def pip_project_remote_dependency_installed():
    """
    Initialize and install a new `pip` project with a remote dependency from PyPI.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(
        tempdir_path,
        TEST_PACKAGE_NAME,
        TEST_PACKAGE_VERSION,
        dependencies=[(REMOTE_PACKAGE_NAME, REMOTE_PACKAGE_VERSION)],
        installed=True,
    )

    tempdir.cleanup()


@pytest.fixture
def pip_project_local_dependency():
    """
    Initialize a new `pip` project with a local dependency.
    """
    local_dependency_tempdir = TemporaryDirectory()
    local_dependency_tempdir_path = Path(local_dependency_tempdir.name)

    local_dependency_path = init_pip_project(
        local_dependency_tempdir_path,
        LOCAL_PACKAGE_NAME,
        LOCAL_PACKAGE_VERSION,
    )

    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(
        tempdir_path,
        TEST_PACKAGE_NAME,
        TEST_PACKAGE_VERSION,
        dependencies=[(LOCAL_PACKAGE_NAME, local_dependency_path)],
    )

    tempdir.cleanup()
    local_dependency_tempdir.cleanup()


@pytest.fixture
def pip_project_local_dependency_installed():
    """
    Initialize and install a new `pip` project with a local dependency.
    """
    local_dependency_tempdir = TemporaryDirectory()
    local_dependency_tempdir_path = Path(local_dependency_tempdir.name)

    local_dependency_path = init_pip_project(
        local_dependency_tempdir_path,
        LOCAL_PACKAGE_NAME,
        LOCAL_PACKAGE_VERSION,
    )

    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    yield init_pip_project(
        tempdir_path,
        TEST_PACKAGE_NAME,
        TEST_PACKAGE_VERSION,
        dependencies=[(LOCAL_PACKAGE_NAME, local_dependency_path)],
        installed=True,
    )

    tempdir.cleanup()
    local_dependency_tempdir.cleanup()


def init_pip_project(
    parent: Path,
    package_name: str,
    package_version: str,
    dependencies: Optional[list[tuple[str, str] | tuple[str, Path]]] = None,
    installed: bool = False,
) -> Path:
    """
    Initialize a new `pip` project in the given directory and with the given parameters.
    """
    project_dir = parent / package_name
    project_dir.mkdir()

    venv_dir = project_dir / "venv"
    subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)

    source_dir = project_dir / package_name
    source_dir.mkdir()
    (source_dir / "__init__.py").touch()

    pyproject_path = project_dir / "pyproject.toml"
    with open(pyproject_path, 'w') as f:
        f.write(generate_pyproject_toml(package_name, package_version, dependencies))

    if installed:
        venv_pip = venv_dir / "bin" / "pip"
        subprocess.run([venv_pip, "install", project_dir], check=True)

    return project_dir


def generate_pyproject_toml(
    package_name: str,
    package_version: str,
    dependencies: Optional[list[tuple[str, str] | tuple[str, Path]]] = None
) -> str:
    """
    Generate `pyproject.toml` content from the given parameters.
    """
    dependency_specs = []
    for dependency in dependencies or []:
        if not (isinstance(dependency, tuple) and len(dependency) == 2):
            raise ValueError(f"Invalid test dependency specification: {dependency}")

        package, spec = dependency
        if not isinstance(package, str):
            raise ValueError(f"Invalid test dependency specification package component: {package}")

        # Dependency sourced from PyPI
        if isinstance(spec, str):
            dependency_specs.append(f'"{package}=={spec}"')
        # Dependency sourced from local directory
        elif isinstance(spec, Path):
            dependency_specs.append(f'"{package} @ file://{spec}"')
        else:
            raise ValueError(f"Invalid test dependency specification spec component: {spec}")

    dependencies_toml = f"dependencies = [{', '.join(dependency_specs)}]" if dependency_specs else ""

    return f"""\
    [build-system]
    requires = ["setuptools"]
    build-backend = "setuptools.build_meta"

    [project]
    name = "{package_name}"
    version = "{package_version}"
    {dependencies_toml}\
    """
