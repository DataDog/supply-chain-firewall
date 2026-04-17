"""
Provides a collection of common fixtures for the pip tests.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

LOCAL_PACKAGE_NAME = "foo"
LOCAL_PACKAGE_VERSION = "0.1.0"

LOCAL_PACKAGE_SETUP_FILE = f"""\
from setuptools import setup, find_packages

setup(
    name='{LOCAL_PACKAGE_NAME}',
    version='{LOCAL_PACKAGE_VERSION}',
    packages=find_packages(),
)
"""


@pytest.fixture
def local_python_package():
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)

    # Create a minimally installable local Python package
    local_package_dir = tempdir_path / LOCAL_PACKAGE_NAME
    local_package_dir.mkdir()

    source_dir = local_package_dir / LOCAL_PACKAGE_NAME
    source_dir.mkdir()
    init_file_path = source_dir / "__init__.py"
    init_file_path.touch()

    setup_file = local_package_dir / "setup.py"
    with open(setup_file, 'w') as f:
        f.write(LOCAL_PACKAGE_SETUP_FILE)

    yield local_package_dir

    tempdir.cleanup()
