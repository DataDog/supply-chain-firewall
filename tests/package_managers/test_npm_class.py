"""
Tests of `Npm`, the `PackageManager` subclass.
"""

from pathlib import Path
from typing import Optional

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.npm import Npm

from .npm_fixtures import *

PACKAGE_MANAGER = Npm()
"""
Fixed `PackageManager` to use across all tests.
"""

TEST_PACKAGE_LATEST_INSTALL_TARGETS = {
    Package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_LATEST),
    Package(ECOSYSTEM.Npm, "js-tokens", "4.0.0"),
    Package(ECOSYSTEM.Npm, "loose-envify", "1.4.0"),
}
"""
Known installation targets for `TEST_PACKAGE@TEST_PACKAGE_LATEST`.
"""

TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS = {
    Package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_PREVIOUS),
    Package(ECOSYSTEM.Npm, "js-tokens", "4.0.0"),
    Package(ECOSYSTEM.Npm, "loose-envify", "1.4.0"),
}
"""
Known installation targets for `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS`.
"""


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (["npm", "install", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
    ]
)
def test_resolve_install_targets_empty_directory(
    monkeypatch,
    empty_directory,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an empty directory.
    """
    backend_test_resolve_install_targets(monkeypatch, empty_directory, command, true_targets)


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (["npm", "install", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
    ]
)
def test_resolve_install_targets_new_project(
    monkeypatch,
    new_npm_project,
    command: list[str],
    true_targets: Optional[set[Package]]
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in a new `npm` project with no dependencies.
    """
    backend_test_resolve_install_targets(monkeypatch, new_npm_project, command, true_targets)


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (["npm", "install", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (["npm", "install", TEST_PACKAGE_PREVIOUS_SPEC], TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS),
    ]
)
def test_resolve_install_targets_dependency_latest(
    monkeypatch,
    npm_project_dependency_latest,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an npm project with a specified dependency.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_dependency_latest,
        command,
        true_targets,
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            TEST_PACKAGE_LATEST_INSTALL_TARGETS,
        ),
        (
            ["npm", "install", TEST_PACKAGE_PREVIOUS_SPEC],
            TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS,
        ),
    ]
)
def test_resolve_install_targets_dependency_latest_lockfile(
    monkeypatch,
    npm_project_dependency_latest_lockfile,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an npm project with a specified dependency and a lockfile but no installed
    dependencies and in which we can downgrade a dependency.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_dependency_latest_lockfile,
        command,
        true_targets,
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (["npm", "install", TEST_PACKAGE_LATEST_SPEC], None),
        (
            ["npm", "install", TEST_PACKAGE_PREVIOUS_SPEC],
            {Package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)},
        ),
    ]
)
def test_resolve_install_targets_installed_latest(
    monkeypatch,
    npm_project_installed_latest,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in a fully installed npm project and in which we can downgrade a dependency.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_installed_latest,
        command,
        true_targets,
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS),
        (
            ["npm", "install", TEST_PACKAGE_PREVIOUS_SPEC],
            TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS,
        ),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            TEST_PACKAGE_LATEST_INSTALL_TARGETS,
        ),
    ]
)
def test_resolve_install_targets_dependency_previous_lockfile(
    monkeypatch,
    npm_project_dependency_previous_lockfile,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an npm project with a specified dependency and a lockfile but no installed
    dependencies and in which we can upgrade a dependency.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_dependency_previous_lockfile,
        command,
        true_targets,
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (["npm", "install", TEST_PACKAGE_PREVIOUS_SPEC], None),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            {Package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_LATEST)},
        ),
    ]
)
def test_resolve_install_targets_installed_previous(
    monkeypatch,
    npm_project_installed_previous,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in a fully installed npm project where we can upgrade a dependency.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_installed_previous,
        command,
        true_targets,
    )


def test_npm_list_installed_packages(monkeypatch, npm_project_installed_latest):
    """
    Test that `Npm.list_installed_packages` correctly parses `npm` output.
    """
    monkeypatch.chdir(npm_project_installed_latest)

    installed_packages = PACKAGE_MANAGER.list_installed_packages()

    assert len(installed_packages) == len(TEST_PACKAGE_LATEST_INSTALL_TARGETS)
    assert set(installed_packages) == TEST_PACKAGE_LATEST_INSTALL_TARGETS


def backend_test_resolve_install_targets(
    monkeypatch,
    project: Path,
    command: list[str],
    true_targets: Optional[set[Package]],
):
    """
    Backend function for testing that the `Npm.resolve_install_targets()` method
    correctly identifies install targets and does not modify the project state.
    """
    monkeypatch.chdir(project)
    initial_state = get_npm_project_state(project)

    targets = PACKAGE_MANAGER.resolve_install_targets(command)

    if true_targets is None:
        assert not targets
    else:
        assert len(targets) == len(true_targets)
        assert set(targets) == true_targets

    assert get_npm_project_state(project) == initial_state


def get_npm_project_state(project_path: Path) -> str:
    """
    Return the current state of installed packages in the given npm project.
    """
    npm_list_command = ["npm", "list", "--all"]
    npm_list_process = subprocess.run(
        npm_list_command,
        text=True,
        capture_output=True,
        cwd=project_path
    )

    return npm_list_process.stdout.strip()
