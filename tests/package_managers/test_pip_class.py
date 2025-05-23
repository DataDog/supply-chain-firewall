"""
Tests of `Pip`, the `PackageManager` subclass.
"""

import shutil

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.pip import Pip

from .test_pip import INIT_PIP_STATE, TEST_TARGET, pip_list

PACKAGE_MANAGER = Pip()
"""
Fixed `PackageManager` to use across all tests.
"""


def test_executable():
    """
    Test whether `Pip` correctly discovers the Python executable active in the
    current environment.
    """
    python = shutil.which("python")
    assert python and PACKAGE_MANAGER.executable() == python


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
            (["pip", "install", "--non-existent-option", TEST_TARGET], False)
        ]
)
def test_pip_command_would_install(command_line: list[str], has_targets: bool):
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


def test_pip_command_would_install_exact():
    """
    Test that `Pip.resolve_install_targets` gives the right answer relative to
    an exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: Package(ECOSYSTEM.PyPI, p[0], p[1]),
            [
                ("botocore", "1.15.0"),
                ("docutils", "0.15.2"),
                ("jmespath", "0.10.0"),
                ("python-dateutil", "2.9.0.post0"),
                ("six", "1.17.0"),
                ("urllib3", "1.25.11")
            ]
        )
    )

    command_line = ["pip", "install", "--ignore-installed", "botocore==1.15.0"]
    targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)
