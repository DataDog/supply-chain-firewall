"""
Tests of `Pip`, the `PackageManager` subclass.
"""

import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package, RemotePackageSource
from scfw.package_managers.pip import Pip

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list

PACKAGE_MANAGER = Pip()
"""
Fixed `PackageManager` to use across all tests.
"""


def test_executable():
    """
    Test whether `Pip` correctly discovers the pip executable active in the
    current environment.
    """
    pip = shutil.which("pip3") or shutil.which("pip")
    assert pip and PACKAGE_MANAGER.executable() == pip


@pytest.mark.parametrize(
        "command_line,has_targets",
        [
            (["pip", "install", TEST_TARGET], True),
            (["pip", "-h", "install", TEST_TARGET], False),
            (["pip", "--help", "install", TEST_TARGET], False),
            (["pip", "install", "-h", TEST_TARGET], False),
            (["pip", "install", "--help", TEST_TARGET], False),
            (["pip", "install" "--dry-run", TEST_TARGET], False),
            (["pip", "--dry-run", "install", TEST_TARGET], False),
            (["pip", "install", "--report", "report.json", TEST_TARGET], True),
            (["pip", "install", "--non-existent-option", TEST_TARGET], False),
            (["pip", "install", "-v", TEST_TARGET], True),
            (["pip", "install", "-vv", TEST_TARGET], True),
            (["pip", "install", "-vvv", TEST_TARGET], True),
            (["pip", "install", "-vvvv", TEST_TARGET], True),
            (["pip", "install", "--verbose", TEST_TARGET], True),
            (["pip", "install", "--verbose", "--verbose", TEST_TARGET], True),
            (["pip", "install", "--verbose", "--verbose", "--verbose", TEST_TARGET], True),
            (["pip", "install", "--verbose", "--verbose", "--verbose", "--verbose", TEST_TARGET], True),
        ]
)
def test_pip_command_resolve_install_targets(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that a `Pip.resolve_install_targets` call
    either does or does not have install targets and does not modify the
    local pip installation state.
    """
    targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
    if has_targets:
        assert targets
    else:
        assert not targets
    assert pip_list() == INIT_PIP_STATE


def test_pip_command_resolve_install_targets_exact():
    """
    Test that `Pip.resolve_install_targets` gives the right answer relative to
    an exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: Package(ECOSYSTEM.PyPI, p[0], p[1], RemotePackageSource(p[2])),
            [
                (
                    "botocore",
                    "1.15.0",
                    "https://files.pythonhosted.org/packages/a4/ba/236f25b9200f0cda4842585205b566979484d38927a8a302cc5c1beea10c/botocore-1.15.0-py2.py3-none-any.whl",
                ),
                (
                    "docutils",
                    "0.15.2",
                    "https://files.pythonhosted.org/packages/22/cd/a6aa959dca619918ccb55023b4cb151949c64d4d5d55b3f4ffd7eee0c6e8/docutils-0.15.2-py3-none-any.whl",
                ),
                (
                    "jmespath",
                    "0.10.0",
                    "https://files.pythonhosted.org/packages/07/cb/5f001272b6faeb23c1c9e0acc04d48eaaf5c862c17709d20e3469c6e0139/jmespath-0.10.0-py2.py3-none-any.whl",
                ),
                (
                    "python-dateutil",
                    "2.9.0.post0",
                    "https://files.pythonhosted.org/packages/ec/57/56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
                ),
                (
                    "six",
                    "1.17.0",
                    "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
                ),
                (
                    "urllib3",
                    "1.25.11",
                    "https://files.pythonhosted.org/packages/56/aa/4ef5aa67a9a62505db124a5cb5262332d1d4153462eb8fd89c9fa41e5d92/urllib3-1.25.11-py2.py3-none-any.whl",
                )
            ]
        )
    )

    command_line = ["pip", "install", "--ignore-installed", "botocore==1.15.0"]
    targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)


def test_pip_list_installed_packages(monkeypatch):
    """
    Test that `Pip.list_installed_packages` correctly parses `pip` output.
    """
    target = Package(ECOSYSTEM.PyPI, "tree-sitter", "0.24.0")

    with TemporaryDirectory() as tmp:
        monkeypatch.chdir(tmp)

        venv_pip = "venv/bin/pip"
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        subprocess.run([venv_pip, "install", f"{target.name}=={target.version}"], check=True)

        assert target in Pip(executable=venv_pip).list_installed_packages()
