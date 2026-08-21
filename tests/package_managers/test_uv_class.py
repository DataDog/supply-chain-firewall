"""
Tests of `Uv`, the `PackageManager` subclass.
"""

import shutil
import subprocess
from tempfile import TemporaryDirectory
from pathlib import Path

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.uv import Uv
from .test_uv import uv_pip_list

PACKAGE_MANAGER = Uv()


def test_executable():
    """
    Test whether `Uv` correctly discovers the uv executable active in the
    current environment.
    """
    uv_exe = shutil.which("uv")
    assert uv_exe and PACKAGE_MANAGER.executable() == uv_exe


def test_metadata():
    """
    Test static properties of the Uv class.
    """
    assert PACKAGE_MANAGER.name() == "uv"
    assert PACKAGE_MANAGER.ecosystem() == ECOSYSTEM.PyPI


@pytest.mark.parametrize(
    "command_line,has_targets",
    [
        (["uv", "sync"], True),
        (["uv", "sync", "-h"], False),
        (["uv", "sync", "--help"], False),
        (["uv", "sync", "-V"], False),
        (["uv", "sync", "--version"], False),
        (["uv", "sync", "--dry-run"], False),
        (["uv", "add", "requests"], False),
        (["uv", "export", "-h"], False),
    ],
)
def test_uv_command_resolve_install_targets(command_line: list[str], has_targets: bool, monkeypatch, tmp_path: Path):
    """
    Test that `Uv.resolve_install_targets` correctly identifies whether commands
    have installation targets or should be skipped via flags/subcommands,
    without modifying the environment.
    """
    init_state = uv_pip_list()

    if has_targets:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\nname = "test-pkg"\nversion = "0.1.0"\ndependencies = ["packaging>=20.0"]\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
        assert targets
        assert any(pkg.name == "packaging" for pkg in targets)
    else:
        targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
        assert not targets

    assert uv_pip_list() == init_state


def test_uv_get_installed_packages(monkeypatch):
    """
    Test that `Uv.get_installed_packages` returns the set of installed packages
    matching the environment state.
    """
    with TemporaryDirectory() as tmp:
        monkeypatch.chdir(tmp)
        tmp_path = Path(tmp)
        venv_dir = tmp_path / ".venv"

        subprocess.run([PACKAGE_MANAGER.executable(), "venv", str(venv_dir)], check=True)

        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        subprocess.run(
            [PACKAGE_MANAGER.executable(), "pip", "install", "packaging==24.0"],
            check=True,
        )

        installed_packages = PACKAGE_MANAGER.get_installed_packages()

        target_package = Package(ECOSYSTEM.PyPI, "packaging", "24.0")
        assert target_package in installed_packages
