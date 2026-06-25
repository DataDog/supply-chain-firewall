"""
Tests of `Npm`, the `PackageManager` subclass.
"""

import json
import logging
from pathlib import Path
import subprocess
from typing import Optional

import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package, LocalPackageSource, RemotePackageSource
from scfw.package_managers.npm import Npm
import scfw.package_managers.npm as npm

from .npm_fixtures import (
    LOCAL_PACKAGE_NAME,
    LOCAL_PACKAGE_VERSION,
    TEST_PACKAGE,
    TEST_PACKAGE_LATEST,
    TEST_PACKAGE_LATEST_DEPENDENCIES,
    TEST_PACKAGE_LATEST_SPEC,
    TEST_PACKAGE_PREVIOUS,
    TEST_PACKAGE_PREVIOUS_DEPENDENCIES,
    TEST_PACKAGE_PREVIOUS_SPEC,
)
from .. import utils

PACKAGE_MANAGER = Npm()
"""
Fixed `PackageManager` to use across all tests.
"""

TEST_PACKAGE_LATEST_INSTALL_TARGETS = {
    utils.build_registry_package(ECOSYSTEM.Npm, name, version)
    for name, version in TEST_PACKAGE_LATEST_DEPENDENCIES
}
"""
`Package` representations of the known dependencies of `TEST_PACKAGE@TEST_PACKAGE_LATEST`.
"""

TEST_PACKAGE_PREVIOUS_INSTALL_TARGETS = {
    utils.build_registry_package(ECOSYSTEM.Npm, name, version)
    for name, version in TEST_PACKAGE_PREVIOUS_DEPENDENCIES
}
"""
`Package` representations of the known dependencies of `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS`.
"""


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (["npm", "install", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (["npm", "install", "-g", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (["npm", "install", "--global", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
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
        (["npm", "install", "-g", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
        (["npm", "install", "--global", TEST_PACKAGE_LATEST_SPEC], TEST_PACKAGE_LATEST_INSTALL_TARGETS),
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
            {utils.build_registry_package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)},
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
            {utils.build_registry_package(ECOSYSTEM.Npm, TEST_PACKAGE, TEST_PACKAGE_LATEST)},
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


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (
            ["npm", "install"],
            {Package(ECOSYSTEM.Npm, LOCAL_PACKAGE_NAME, LOCAL_PACKAGE_VERSION)}
        ),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            TEST_PACKAGE_LATEST_INSTALL_TARGETS | {Package(ECOSYSTEM.Npm, LOCAL_PACKAGE_NAME, LOCAL_PACKAGE_VERSION)},
        )
    ]
)
def test_resolve_install_targets_local_dependency(
    monkeypatch,
    npm_project_local_dependency,
    command,
    true_targets,
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an npm project with a dependency on a local package.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_local_dependency,
        command,
        patch_local_dependency_targets(npm_project_local_dependency, true_targets),
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (
            ["npm", "install"],
            {Package(ECOSYSTEM.Npm, LOCAL_PACKAGE_NAME, LOCAL_PACKAGE_VERSION)}
        ),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            TEST_PACKAGE_LATEST_INSTALL_TARGETS | {Package(ECOSYSTEM.Npm, LOCAL_PACKAGE_NAME, LOCAL_PACKAGE_VERSION)},
        )
    ]
)
def test_resolve_install_targets_local_dependency_lockfile(
    monkeypatch,
    npm_project_local_dependency_lockfile,
    command,
    true_targets,
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in an npm project with a dependency on a local package specified in its lockfile
    but not installed.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_local_dependency_lockfile,
        command,
        patch_local_dependency_targets(npm_project_local_dependency_lockfile, true_targets),
    )


@pytest.mark.parametrize(
    "command, true_targets",
    [
        (["npm", "install"], None),
        (
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC],
            TEST_PACKAGE_LATEST_INSTALL_TARGETS,
        ),
    ]
)
def test_resolve_install_targets_local_dependency_installed(
    monkeypatch,
    npm_project_local_dependency_installed,
    command,
    true_targets,
):
    """
    Test that `Npm` correctly resolves installation targets for `npm install` commands
    run in a fully installed npm project with a dependency on a local package.
    """
    backend_test_resolve_install_targets(
        monkeypatch,
        npm_project_local_dependency_installed,
        command,
        true_targets,
    )


def test_get_installed_packages_empty_directory(monkeypatch, empty_directory):
    """
    Test that `Npm` correctly identifies installed packages in an empty directory.
    """
    backend_test_get_installed_packages(
        monkeypatch,
        empty_directory,
        should_fail=False,
        installed=set(),
    )


def test_get_installed_packages_new_npm_project(monkeypatch, new_npm_project):
    """
    Test that `Npm` correctly identifies installed packages in a new npm project
    with no dependencies.
    """
    backend_test_get_installed_packages(
        monkeypatch,
        new_npm_project,
        should_fail=False,
        installed=set(),
    )


def test_get_installed_packages_dependency_latest(monkeypatch, npm_project_dependency_latest):
    """
    Test that `Npm` correctly identifies installed packages in a new npm project
    with an uninstalled dependency. `npm list` exits non-zero with ELSPROBLEMS in
    this case, but the JSON report it writes to stdout is still consumed, and the
    declared-but-uninstalled dependency is reported as not installed.
    """
    backend_test_get_installed_packages(
        monkeypatch,
        npm_project_dependency_latest,
        should_fail=False,
        installed=set(),
    )


def test_get_installed_packages_dependency_latest_lockfile(
    monkeypatch,
    npm_project_dependency_latest_lockfile
):
    """
    Test that `Npm` correctly identifies installed packages in a new npm project
    with an uninstalled dependency and a lockfile. As above, `npm list` exits
    non-zero but its JSON report is still consumed.
    """
    backend_test_get_installed_packages(
        monkeypatch,
        npm_project_dependency_latest_lockfile,
        should_fail=False,
        installed=set(),
    )


def test_get_installed_packages_installed_latest(monkeypatch, npm_project_installed_latest):
    """
    Test that `Npm` correctly identifies installed packages in an npm project
    with an installed dependency.
    """
    backend_test_get_installed_packages(
        monkeypatch,
        npm_project_installed_latest,
        should_fail=False,
        installed=TEST_PACKAGE_LATEST_INSTALL_TARGETS,
    )


def test_get_installed_packages_local_dependency_installed(
    monkeypatch,
    npm_project_local_dependency_installed,
):
    """
    Test that `Npm.get_installed_packages` reports an installed local file:
    dependency with its `LocalPackageSource` populated to the original source path.
    """
    expected_source = (
        npm_project_local_dependency_installed.parent / LOCAL_PACKAGE_NAME
    ).resolve(strict=True)

    backend_test_get_installed_packages(
        monkeypatch,
        npm_project_local_dependency_installed,
        should_fail=False,
        installed={
            Package(
                ECOSYSTEM.Npm,
                LOCAL_PACKAGE_NAME,
                LOCAL_PACKAGE_VERSION,
                source=LocalPackageSource(expected_source),
            ),
        },
    )


def test_get_installed_packages_uses_root_lockfile_for_missing_resolved(monkeypatch, tmp_path):
    """
    When `npm list` omits `resolved` for a deduped package but the root
    package-lock.json has it, `Npm.get_installed_packages` populates source from
    the lock file instead of leaving it None.
    """
    resolved_url = "https://registry.npmjs.org/deduped-pkg/-/deduped-pkg-1.0.0.tgz"
    npm_list_output = json.dumps({
        "dependencies": {
            "parent-pkg": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/parent-pkg/-/parent-pkg-2.0.0.tgz",
                "dependencies": {
                    "deduped-pkg": {"version": "1.0.0"},
                },
            },
        },
    })
    lock_file_content = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/deduped-pkg": {"version": "1.0.0", "resolved": resolved_url},
        },
    })
    (tmp_path / "package-lock.json").write_text(lock_file_content)

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    packages = PACKAGE_MANAGER.get_installed_packages()

    assert Package(
        ECOSYSTEM.Npm, "deduped-pkg", "1.0.0", source=RemotePackageSource(resolved_url)
    ) in packages


def test_get_installed_packages_uses_root_lockfile_for_non_hoisted_packages(monkeypatch, tmp_path):
    """
    When a transitive dep can't be hoisted (version conflict with a top-level dep),
    the lock file records it under `node_modules/<parent>/node_modules/<child>`.
    The fallback map must still resolve `<child>` from such an entry.
    """
    nested_url = "https://registry.npmjs.org/conflict-pkg/-/conflict-pkg-2.0.0.tgz"
    npm_list_output = json.dumps({
        "dependencies": {
            "parent-pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/parent-pkg/-/parent-pkg-1.0.0.tgz",
                "dependencies": {
                    "conflict-pkg": {"version": "2.0.0"},
                },
            },
        },
    })
    lock_file_content = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/conflict-pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/conflict-pkg/-/conflict-pkg-1.0.0.tgz",
            },
            "node_modules/parent-pkg/node_modules/conflict-pkg": {
                "version": "2.0.0",
                "resolved": nested_url,
            },
        },
    })
    (tmp_path / "package-lock.json").write_text(lock_file_content)

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    packages = PACKAGE_MANAGER.get_installed_packages()

    assert Package(
        ECOSYSTEM.Npm, "conflict-pkg", "2.0.0", source=RemotePackageSource(nested_url)
    ) in packages


def test_get_installed_packages_uses_local_dep_lockfile_for_transitive_packages(
    monkeypatch, tmp_path
):
    """
    When a local file: dependency's transitive packages lack `resolved` in
    `npm list` output, get_installed_packages uses the local package's own
    package-lock.json to populate source.
    """
    transitive_url = "https://registry.npmjs.org/transitive-pkg/-/transitive-pkg-3.0.0.tgz"

    node_modules_dir = tmp_path / "node_modules"
    node_modules_dir.mkdir()
    local_pkg_dir = tmp_path / "my-local-pkg"
    local_pkg_dir.mkdir()
    (local_pkg_dir / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/transitive-pkg": {"version": "3.0.0", "resolved": transitive_url},
        },
    }))

    npm_list_output = json.dumps({
        "dependencies": {
            "my-local-pkg": {
                "version": "1.0.0",
                "resolved": "file:../my-local-pkg",
                "dependencies": {
                    "transitive-pkg": {"version": "3.0.0"},
                },
            },
        },
    })

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    packages = PACKAGE_MANAGER.get_installed_packages()

    assert Package(
        ECOSYSTEM.Npm, "transitive-pkg", "3.0.0", source=RemotePackageSource(transitive_url)
    ) in packages


def test_get_installed_packages_silently_skips_uninstalled_deps(monkeypatch, tmp_path, caplog):
    """
    Dependencies that appear in `npm list` with no version field (e.g. uninstalled
    optional peer deps) are silently skipped — no WARNING is emitted.
    """
    good_url = "https://registry.npmjs.org/good-package/-/good-package-1.2.3.tgz"
    npm_list_output = json.dumps({
        "dependencies": {
            "good-package": {"version": "1.2.3", "resolved": good_url},
            "uninstalled-peer": {},
        },
    })

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.WARNING, logger="scfw.package_managers.npm"):
        packages = PACKAGE_MANAGER.get_installed_packages()

    assert packages == {Package(ECOSYSTEM.Npm, "good-package", "1.2.3", source=RemotePackageSource(good_url))}
    assert not any("uninstalled-peer" in r.message for r in caplog.records if r.levelno >= logging.WARNING)


def test_get_installed_packages_keeps_dep_with_missing_local_source(monkeypatch, tmp_path):
    """
    Regression test: when `npm list` reports a `file:` dep whose target does
    not exist on disk, `Npm.get_installed_packages` should still return the
    package (without source data) instead of silently dropping it.
    """
    npm_list_output = json.dumps({
        "dependencies": {
            "ghost-package": {
                "version": "1.0.0",
                "resolved": "file:./does-not-exist-XYZ",
            },
        },
    })

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    packages = PACKAGE_MANAGER.get_installed_packages()

    assert packages == {Package(ECOSYSTEM.Npm, "ghost-package", "1.0.0")}


def test_get_installed_packages_skips_malformed_entries(monkeypatch, tmp_path):
    """
    Malformed entries (e.g., missing `version`, or a non-dict in place of an
    entry) are dropped with a warning, but well-formed sibling entries are
    still returned.
    """
    good_url = "https://registry.npmjs.org/good-package/-/good-package-1.2.3.tgz"
    npm_list_output = json.dumps({
        "dependencies": {
            "good-package": {
                "version": "1.2.3",
                "resolved": good_url,
            },
            "no-version": {
                "resolved": "https://registry.npmjs.org/no-version/-/no-version-1.0.0.tgz",
            },
            "not-a-dict": "this should have been an object",
        },
    })

    class FakeCompletedProcess:
        stdout = npm_list_output
        stderr = ""
        returncode = 0

    monkeypatch.setattr(npm.installed.subprocess, "run", lambda *args, **kwargs: FakeCompletedProcess())
    monkeypatch.setattr(PACKAGE_MANAGER, "_check_version", lambda: None)
    monkeypatch.chdir(tmp_path)

    packages = PACKAGE_MANAGER.get_installed_packages()

    assert packages == {
        Package(ECOSYSTEM.Npm, "good-package", "1.2.3", source=RemotePackageSource(good_url)),
    }


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


def backend_test_get_installed_packages(
    monkeypatch,
    project: Path,
    should_fail: bool,
    installed: set[Package],
):
    """
    Backend function for testing that the `Npm.get_installed_packages()` method
    correctly identifies installed packages or fails to do so in the given `project`.

    Args:
        project: A `Path` to the directory where `npm list` should be tested.
        should_fail: A `bool` indicating whether the `npm list` command should fail.
        installed:
            The (possibly empty) set of `Package` that should be installed in `project`.
    """
    monkeypatch.chdir(project)

    if should_fail:
        with pytest.raises(RuntimeError):
            PACKAGE_MANAGER.get_installed_packages()
        return

    experiment = PACKAGE_MANAGER.get_installed_packages()
    assert len(experiment) == len(installed)
    assert experiment == installed


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


def patch_local_dependency_targets(test_project: Path, targets: set[Package]) -> set[Package]:
    """
    Add local package source data for local test dependencies.
    """
    patched_targets = list(targets)

    for i, target in enumerate(patched_targets):
        if target.name == LOCAL_PACKAGE_NAME:
            patched_targets[i] = Package(
                ecosystem=target.ecosystem,
                name=target.name,
                version=target.version,
                source=LocalPackageSource(
                    (test_project.parent / LOCAL_PACKAGE_NAME).resolve(strict=True)
                ),
            )

    return set(patched_targets)
