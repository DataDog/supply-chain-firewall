"""
Tests for the Bun package manager implementation.
"""

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

import pytest

from scfw.package_managers.bun import Bun
from scfw.package import Package
from scfw.ecosystem import ECOSYSTEM


@pytest.fixture
def bun():
    """
    Provide a Bun package manager instance.
    """
    return Bun()


def test_bun_name(bun):
    """
    Test that Bun.name() returns 'bun'.
    """
    assert bun.name() == "bun"


def test_bun_ecosystem(bun):
    """
    Test that Bun.ecosystem() returns ECOSYSTEM.Npm.
    """
    assert bun.ecosystem() == ECOSYSTEM.Npm


def test_bun_executable(bun):
    """
    Test that Bun.executable() returns a valid path.
    """
    assert bun.executable() is not None
    assert os.path.isfile(bun.executable())


def test_bun_list_installed_packages(bun):
    """
    Test that bun.list_installed_packages() returns a list of packages
    in a project with dependencies.
    """
    # Create a temporary bun project with a dependency
    with TemporaryDirectory() as tempdir:
        tmppath = Path(tempdir)

        # Initialize bun project
        subprocess.run(["bun", "init", "-y"], check=True, cwd=tmppath)

        # Add a dependency
        subprocess.run(["bun", "add", "react@18.3.0"], check=True, cwd=tmppath)

        # Run list_installed_packages in this directory
        original_cwd = os.getcwd()
        try:
            os.chdir(tmppath)
            packages = bun.list_installed_packages()

            assert isinstance(packages, list)
            assert len(packages) > 0

            # Verify package structure
            for pkg in packages:
                assert isinstance(pkg, Package)
                assert pkg.ecosystem == ECOSYSTEM.Npm
                assert pkg.name
                assert pkg.version

        finally:
            os.chdir(original_cwd)


def test_bun_resolve_install_targets_dry_run(bun):
    """
    Test that bun.resolve_install_targets() correctly resolves from a dry-run command.
    """
    # Create a temporary bun project
    with TemporaryDirectory() as tempdir:
        tmppath = Path(tempdir)

        # Initialize bun project
        subprocess.run(["bun", "init", "-y"], check=True, cwd=tmppath)

        # Run resolve_install_targets in this directory
        original_cwd = os.getcwd()
        try:
            os.chdir(tmppath)
            command = ["bun", "add", "chalk@5.3.0", "--dry-run"]
            packages = bun.resolve_install_targets(command)

            assert isinstance(packages, list)

            # Should find the target package
            target_packages = [p for p in packages if p.name == "chalk"]
            assert len(target_packages) > 0
            assert target_packages[0].version == "5.3.0"

        finally:
            os.chdir(original_cwd)


def test_bun_resolve_install_targets_non_install_command(bun):
    """
    Test that bun.resolve_install_targets() returns empty list for non-install commands.
    """
    command = ["bun", "run", "test"]
    packages = bun.resolve_install_targets(command)

    assert isinstance(packages, list)
    assert len(packages) == 0


def test_bun_run_command_success(bun):
    """
    Test that bun.run_command() returns 0 for successful commands.
    """
    # Test bun --version
    result = bun.run_command(["bun", "--version"])
    assert result == 0


def test_bun_version_format(bun):
    """
    Test that Bun can handle bun's version string format.
    """
    # bun version format: "1.3.8+b64edcb49" or "1.3.8"
    # This is tested in the class initialization through _check_version()

    # If we got here, version check passed
    assert os.path.isfile(bun.executable())
