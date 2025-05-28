"""
Tests of `Poetry`, the `PackageManager` subclass.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.poetry import Poetry

from .test_poetry import (
    POETRY_V2, TARGET, TARGET_LATEST, TARGET_PREVIOUS, TEST_PROJECT_NAME,
    new_poetry_project, poetry_project_lock_latest,
    poetry_project_target_latest, poetry_project_target_latest_lock_previous,
    poetry_project_target_previous, poetry_project_target_previous_lock_latest,
    poetry_show, poetry_version,
)

PACKAGE_MANAGER = Poetry()
"""
Fixed `PackageManager` to use across all tests.
"""

TARGET_REPO = f"https://github.com/{TARGET}/py-tree-sitter"


def test_poetry_command_resolve_install_targets_add(
    new_poetry_project,
    poetry_project_target_latest,
    poetry_project_target_previous,
):
    """
    Tests that `Poetry.resolve_install_targets()` for a `poetry add` command
    correctly resolves installation targets for a variety of target specfications
    without installing anything.
    """
    test_cases = [
        (new_poetry_project, "{}", TARGET, None),
        (new_poetry_project, "{}@latest", TARGET, None),
        (new_poetry_project, "{}=={}", TARGET, TARGET_LATEST),
        (new_poetry_project, "git+{}", TARGET_REPO, None),
        (new_poetry_project, "git+{}#v{}", TARGET_REPO, TARGET_LATEST),
        (new_poetry_project, "git+{}.git", TARGET_REPO, None),
        (new_poetry_project, "git+{}.git#v{}", TARGET_REPO, TARGET_LATEST),
        (new_poetry_project, "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, TARGET_LATEST),
        (poetry_project_target_latest, "{}=={}", TARGET, TARGET_PREVIOUS),
        (poetry_project_target_latest, "git+{}#v{}", TARGET_REPO, TARGET_PREVIOUS),
        (poetry_project_target_latest, "git+{}.git#v{}", TARGET_REPO, TARGET_PREVIOUS),
        (poetry_project_target_latest, "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, TARGET_PREVIOUS),
        (poetry_project_target_previous, "{}=={}", TARGET, TARGET_LATEST),
        (poetry_project_target_previous, "git+{}#v{}", TARGET_REPO, TARGET_LATEST),
        (poetry_project_target_previous, "git+{}.git#v{}", TARGET_REPO, TARGET_LATEST),
        (poetry_project_target_previous, "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, TARGET_LATEST),
    ]

    for poetry_project, target_spec, target_name, target_version in test_cases:
        if target_version is None:
            target_spec = target_spec.format(target_name)
            target_version = TARGET_LATEST
        else:
            target_spec = target_spec.format(target_name, target_version)

        init_state = poetry_show(poetry_project)

        targets = PACKAGE_MANAGER.resolve_install_targets(
            ["poetry", "add", "--directory", poetry_project, target_spec]
        )

        assert (
            len(targets) == 1
            and targets[0].ecosystem == ECOSYSTEM.PyPI
            and targets[0].name == TARGET
            and targets[0].version == target_version
        )
        assert poetry_show(poetry_project) == init_state


def test_poetry_command_resolve_install_targets_install(
    new_poetry_project,
    poetry_project_target_latest,
    poetry_project_target_latest_lock_previous,
    poetry_project_target_previous_lock_latest,
):
    """
    Tests that `Poetry.resolve_install_targets()` for a `poetry install` command
    correctly resolves installation targets without installing anything.
    """
    test_cases = [
        (new_poetry_project, [(TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_latest, [(TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_latest_lock_previous, [(TARGET, TARGET_PREVIOUS), (TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_previous_lock_latest, [(TARGET, TARGET_LATEST), (TEST_PROJECT_NAME, "0.1.0")]),
    ]

    assert all(
        _test_poetry_command_resolve_install_targets(["poetry", "install", "--directory", project], project, targets)
        for project, targets in test_cases
    )


def test_poetry_command_resolve_install_targets_sync(
    new_poetry_project,
    poetry_project_target_latest,
    poetry_project_target_previous,
    poetry_project_target_latest_lock_previous,
    poetry_project_target_previous_lock_latest,
):
    """
    Tests that `Poetry.resolve_install_targets()` for a `poetry sync` command
    correctly resolves installation targets without installing anything.
    """
    if poetry_version() < POETRY_V2:
        return

    test_cases = [
        (new_poetry_project, [(TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_latest, [(TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_previous, [(TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_latest_lock_previous, [(TARGET, TARGET_PREVIOUS), (TEST_PROJECT_NAME, "0.1.0")]),
        (poetry_project_target_previous_lock_latest, [(TARGET, TARGET_LATEST), (TEST_PROJECT_NAME, "0.1.0")]),
    ]

    assert all(
        _test_poetry_command_resolve_install_targets(["poetry", "sync", "--directory", project], project, targets)
        for project, targets in test_cases
    )


def test_poetry_command_resolve_install_targets_update(
    poetry_project_lock_latest,
    poetry_project_target_latest_lock_previous,
    poetry_project_target_previous_lock_latest,
):
    """
    Tests that `Poetry.resolve_install_targets()` for a `poetry update` command
    correctly resolves installation targets without installing anything.
    """
    test_cases = [
        (poetry_project_lock_latest, [(TARGET, TARGET_LATEST)]),
        (poetry_project_target_latest_lock_previous, [(TARGET, TARGET_PREVIOUS)]),
        (poetry_project_target_previous_lock_latest, [(TARGET, TARGET_LATEST)]),
    ]

    assert all(
        _test_poetry_command_resolve_install_targets(["poetry", "update", "--directory", project], project, targets)
        for project, targets in test_cases
    )


def test_poetry_list_installed_packages(monkeypatch, poetry_project_target_latest):
    """
    Tests that `Poetry.list_installed_packages` correctly parses `poetry` output.
    """
    # Change directories into the test project directory for only this test
    monkeypatch.chdir(poetry_project_target_latest)

    assert PACKAGE_MANAGER.list_installed_packages() == [Package(ECOSYSTEM.PyPI, TARGET, TARGET_LATEST)]


def _test_poetry_command_resolve_install_targets(command, project, targets) -> bool:
    """
    Tests that `Poetry.resolve_install_targets()` correctly resolves installation
    targets without installing anything.
    """
    init_state = poetry_show(project)

    targets = [Package(ECOSYSTEM.PyPI, name, version) for name, version in targets]

    return PACKAGE_MANAGER.resolve_install_targets(command) == targets and poetry_show(project) == init_state
