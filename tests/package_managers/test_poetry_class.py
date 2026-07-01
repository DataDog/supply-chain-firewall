"""
Tests of `Poetry`, the `PackageManager` subclass.
"""

import shutil
from pathlib import Path

from scfw.ecosystem import ECOSYSTEM
from scfw.package import LocalPackageSource, Package, RemotePackageSource
from scfw.package_managers.poetry import Poetry, _get_source_map

from .poetry_fixtures import (
    TARGET,
    TARGET_LATEST,
    TARGET_PREVIOUS,
    TEST_PROJECT_NAME,
)
from .test_poetry import POETRY_V2, poetry_show, poetry_version

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

        assert len(targets) == 1

        target = targets.pop()
        assert target.ecosystem == ECOSYSTEM.PyPI
        assert target.name == TARGET
        assert target.version == target_version
        # source may be None for packages not yet present in the lock file

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
    version = poetry_version()
    assert version

    if version < POETRY_V2:
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


def test_poetry_get_installed_packages(monkeypatch, poetry_project_target_latest):
    """
    Tests that `Poetry.get_installed_packages` correctly parses `poetry` output.
    """
    # Change directories into the test project directory for only this test
    monkeypatch.chdir(poetry_project_target_latest)

    assert PACKAGE_MANAGER.get_installed_packages() == {Package(ECOSYSTEM.PyPI, TARGET, TARGET_LATEST)}


def _test_poetry_command_resolve_install_targets(command, project, targets) -> bool:
    """
    Tests that `Poetry.resolve_install_targets()` correctly resolves installation
    targets without installing anything, and that each resolved package has a source.
    """
    init_state = poetry_show(project)

    expected = {(ECOSYSTEM.PyPI, name, version) for name, version in targets}
    resolved = PACKAGE_MANAGER.resolve_install_targets(command)
    resolved_identity = {(p.ecosystem, p.name, p.version) for p in resolved}
    # The root project package is not a third-party dep and may not appear in the lock file
    third_party = [p for p in resolved if p.name != TEST_PROJECT_NAME]
    sources_populated = all(p.source is not None for p in third_party)

    return resolved_identity == expected and sources_populated and poetry_show(project) == init_state


def test_resolve_install_targets_pypi_source(poetry_project_target_previous_lock_latest):
    """
    Tests that packages resolved by `Poetry.resolve_install_targets()` for an
    install command are sourced from the PyPI registry.
    """
    project = poetry_project_target_previous_lock_latest
    command = ["poetry", "install", "--directory", project]

    targets = PACKAGE_MANAGER.resolve_install_targets(command)
    registry_targets = [t for t in targets if t.name != TEST_PROJECT_NAME]

    assert registry_targets
    assert all(t.has_registry_source() for t in registry_targets)


def test_get_source_map_no_lock(poetry_project_no_lock):
    """
    Tests that `_get_source_map` generates a lock file via `TemporaryPoetryProject`
    when none exists, returning PyPI sources for registry packages, without
    creating a lock file in the original project directory.
    """
    project = Path(poetry_project_no_lock)
    assert not (project / "poetry.lock").exists()

    command = [shutil.which("poetry"), "install", "--directory", str(project)]
    source_map = _get_source_map(shutil.which("poetry"), command)

    assert source_map

    for (name, version), source in source_map.items():
        assert isinstance(source, (LocalPackageSource, RemotePackageSource))

    target_entries = {ver: src for (name, ver), src in source_map.items() if name == TARGET}
    assert target_entries
    assert all(isinstance(src, RemotePackageSource) for src in target_entries.values())
    assert all(src.remote_source.startswith("https://pypi.org/") for src in target_entries.values())

    assert not (project / "poetry.lock").exists()
