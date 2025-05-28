"""
Tests of `Npm`, the `PackageManager` subclass.
"""

import pytest
import subprocess
from tempfile import TemporaryDirectory

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.npm import Npm

from .test_npm import INIT_NPM_STATE, TEST_TARGET, npm_list

PACKAGE_MANAGER = Npm()
"""
Fixed `PackageManager` to use across all tests.
"""


@pytest.mark.parametrize(
        "command_line,has_targets",
        [
            (["npm", "install", TEST_TARGET], True),
            (["npm", "-h", "install", TEST_TARGET], False),
            (["npm", "--help", "install", TEST_TARGET], False),
            (["npm", "install", "-h", TEST_TARGET], False),
            (["npm", "install", "--help", TEST_TARGET], False),
            (["npm", "--dry-run", "install", TEST_TARGET], False),
            (["npm", "install", "--dry-run", TEST_TARGET], False),
            (["npm", "--non-existent-option"], False)
        ]
)
def test_npm_command_would_install(command_line: list[str], has_targets: bool):
    """
    Backend function for testing that an `Npm.resolve_install_targets` call
    either does or does not have install targets and does not modify the local
    npm installation state.
    """
    targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
    if has_targets:
        assert targets
    else:
        assert not targets
    assert npm_list() == INIT_NPM_STATE


def test_npm_command_would_install_exact():
    """
    Test that `Npm.resolve_install_targets` gives the right answer relative to
    an exact top-level installation target and its dependencies.
    """
    true_targets = list(
        map(
            lambda p: Package(ECOSYSTEM.Npm, p[0], p[1]),
            [
                ("js-tokens", "4.0.0"),
                ("loose-envify", "1.4.0"),
                ("react", "18.3.1")
            ]
        )
    )

    command_line = ["npm", "install", "react@18.3.1"]
    targets = PACKAGE_MANAGER.resolve_install_targets(command_line)
    assert len(targets) == len(true_targets)
    assert all(target in true_targets for target in targets)


def test_npm_list_installed_packages(monkeypatch):
    """
    Test that `Npm.list_installed_packages` correctly parses `npm` output.
    """
    target = Package(ECOSYSTEM.Npm, "react", "19.1.0")

    with TemporaryDirectory() as tmp:
        monkeypatch.chdir(tmp)
        subprocess.run(["npm", "install", f"{target.name}@{target.version}"], check=True)
        assert PACKAGE_MANAGER.list_installed_packages() == [target]
