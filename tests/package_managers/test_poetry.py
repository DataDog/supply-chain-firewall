"""
Tests of Poetry's command line behavior.
"""

import re
import subprocess
from typing import Optional

import packaging.version as version
import pytest

from .poetry_fixtures import *

POETRY_V2 = version.parse("2.0.0")


def test_poetry_version_output():
    """
    Test that `poetry --version` has the required format and parses correctly.
    """
    assert poetry_version() is not None


def test_poetry_add_no_change(new_poetry_project):
    """
    Test that certain `poetry add` commands relied on by Supply-Chain Firewall not
    to error or modify the local installation state indeed have these properties.
    """
    test_cases = [
        ["poetry", "-V", "add", TARGET],
        ["poetry", "add", "-V", TARGET],
        ["poetry", "add", TARGET, "-V"],
        ["poetry", "--version", "add", TARGET],
        ["poetry", "add", "--version", TARGET],
        ["poetry", "add", TARGET, "--version"],
        ["poetry", "-h", "add", TARGET],
        ["poetry", "add", "-h", TARGET],
        ["poetry", "add", TARGET, "-h"],
        ["poetry", "--help", "add", TARGET],
        ["poetry", "add", "--help", TARGET],
        ["poetry", "add", TARGET, "--help"],
        ["poetry", "--dry-run", "add", TARGET],
        ["poetry", "add", "--dry-run", TARGET],
        ["poetry", "add", TARGET, "--dry-run"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_install_no_change(new_poetry_project):
    """
    Test that certain `poetry install` commands relied on by Supply-Chain Firewall
    not to error or modify the local installation state indeed have these properties.
    """
    test_cases = [
        ["poetry", "-V", "install"],
        ["poetry", "install", "-V"],
        ["poetry", "--version", "install"],
        ["poetry", "install", "--version"],
        ["poetry", "-h", "install"],
        ["poetry", "install", "-h"],
        ["poetry", "--help", "install"],
        ["poetry", "install", "--help"],
        ["poetry", "--dry-run", "install"],
        ["poetry", "install", "--dry-run"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_sync_no_change(new_poetry_project):
    """
    Test that certain `poetry sync` commands relied on by Supply-Chain Firewall
    not to error or modify the local installation state indeed have these properties.
    """
    version = poetry_version()
    assert version

    if version < POETRY_V2:
        return

    test_cases = [
        ["poetry", "-V", "sync"],
        ["poetry", "sync", "-V"],
        ["poetry", "--version", "sync"],
        ["poetry", "sync", "--version"],
        ["poetry", "-h", "sync"],
        ["poetry", "sync", "-h"],
        ["poetry", "--help", "sync"],
        ["poetry", "sync", "--help"],
        ["poetry", "--dry-run", "sync"],
        ["poetry", "sync", "--dry-run"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_update_no_change(new_poetry_project):
    """
    Test that certain `poetry update` commands relied on by Supply-Chain Firewall
    not to error or modify the local installation state indeed have these properties.
    """
    test_cases = [
        ["poetry", "-V", "update"],
        ["poetry", "update", "-V"],
        ["poetry", "--version", "update"],
        ["poetry", "update", "--version"],
        ["poetry", "-h", "update"],
        ["poetry", "update", "-h"],
        ["poetry", "--help", "update"],
        ["poetry", "update", "--help"],
        ["poetry", "--dry-run", "update"],
        ["poetry", "update", "--dry-run"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_no_change(new_poetry_project, init_state, command) for command in test_cases)


def _test_poetry_no_change(project, init_state, command) -> bool:
    """
    Tests that a given Poetry command does not encounter any errors and does not
    modify the local installation state when run in the context of a given project.
    """
    subprocess.run(command, check=True, cwd=project)
    return poetry_show(project) == init_state


def test_poetry_add_error_no_change(new_poetry_project):
    """
    Tests that certain `poetry add` commands encounter an error and do not modify
    the local installation state when run in the context of a given project.
    """
    test_cases = [
        ["poetry", "add", "!a_nonexistent_p@ckage_name"],
        ["poetry", "add", "--dry-run", "!a_nonexistent_p@ckage_name"],
        ["poetry", "add", "--nonexistent-option", TARGET],
        ["poetry", "add", "-G", TARGET],
        ["poetry", "add", "--group", TARGET],
        ["poetry", "add", "-E", TARGET],
        ["poetry", "add", "--extras", TARGET],
        ["poetry", "add", "--python", TARGET],
        ["poetry", "add", "--platform", TARGET],
        ["poetry", "add", "--markers", TARGET],
        ["poetry", "add", "--source", TARGET],
        ["poetry", "add", "-P", TARGET],
        ["poetry", "add", "--project", TARGET],
        ["poetry", "add", "-C", TARGET],
        ["poetry", "add", "--directory", TARGET],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_error_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_install_error_no_change(new_poetry_project):
    """
    Tests that certain `poetry install` commands encounter an error and do not
    modify the local installation state when run in the context of a given project.
    """
    test_cases = [
        ["poetry", "install", "unnecessary_argument"],
        ["poetry", "install", "--dry-run", "unnecessary_argument"],
        ["poetry", "install", "--nonexistent-option"],
        ["poetry", "install", "--without"],
        ["poetry", "install", "--with"],
        ["poetry", "install", "--only"],
        ["poetry", "install", "-E"],
        ["poetry", "install", "--extras"],
        ["poetry", "install", "-P"],
        ["poetry", "install", "--project"],
        ["poetry", "install", "-C"],
        ["poetry", "install", "--directory"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_error_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_sync_error_no_change(new_poetry_project):
    """
    Tests that certain `poetry sync` commands encounter an error and do not
    modify the local installation state when run in the context of a given project.
    """
    version = poetry_version()
    assert version

    if version < POETRY_V2:
        return

    test_cases = [
        ["poetry", "sync", "unnecessary_argument"],
        ["poetry", "sync", "--dry-run", "unnecessary_argument"],
        ["poetry", "sync", "--nonexistent-option"],
        ["poetry", "sync", "--without"],
        ["poetry", "sync", "--with"],
        ["poetry", "sync", "--only"],
        ["poetry", "sync", "-E"],
        ["poetry", "sync", "--extras"],
        ["poetry", "sync", "-P"],
        ["poetry", "sync", "--project"],
        ["poetry", "sync", "-C"],
        ["poetry", "sync", "--directory"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_error_no_change(new_poetry_project, init_state, command) for command in test_cases)


def test_poetry_update_error_no_change(new_poetry_project):
    """
    Tests that certain `poetry update` commands encounter an error and do not
    modify the local installation state when run in the context of a given project.
    """
    test_cases = [
        ["poetry", "update", "--nonexistent-option"],
        ["poetry", "update", "--nonexistent-option", TARGET],
        ["poetry", "update", "--without"],
        ["poetry", "update", TARGET, "--without"],
        ["poetry", "update", "--with"],
        ["poetry", "update", TARGET, "--with"],
        ["poetry", "update", "--only"],
        ["poetry", "update", TARGET, "--only"],
        ["poetry", "update", "-P"],
        ["poetry", "update", TARGET, "-P"],
        ["poetry", "update", "--project"],
        ["poetry", "update", TARGET, "--project"],
        ["poetry", "update", "-C"],
        ["poetry", "update", TARGET, "-C"],
        ["poetry", "update", "--directory"],
        ["poetry", "update", TARGET, "--directory"],
    ]

    init_state = poetry_show(new_poetry_project)

    assert all(_test_poetry_error_no_change(new_poetry_project, init_state, command) for command in test_cases)


def _test_poetry_error_no_change(project, init_state, command) -> bool:
    """
    Tests that a given Poetry command does encounter an error and does not modify
    the local installation state when run in the context of a given project.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command, check=True, cwd=project)
    return poetry_show(project) == init_state


def test_poetry_dry_run_output_install(new_poetry_project, poetry_project_lock_latest):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency installation has the expected format.
    """
    def is_install_line(target: str, version: str, line: str) -> bool:
        match = re.search(r"Installing (?:the current project: )?(.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and match.group(2) == version and "Skipped" not in line

    test_cases = [
        (new_poetry_project, ["poetry", "add", "--dry-run", TARGET], TARGET, TARGET_LATEST, None),
        (new_poetry_project, ["poetry", "install", "--dry-run"], TEST_PROJECT_NAME, "0.1.0", None),
        (new_poetry_project, ["poetry", "sync", "--dry-run"], TEST_PROJECT_NAME, "0.1.0", POETRY_V2),
        (poetry_project_lock_latest, ["poetry", "update", "--dry-run"], TARGET, TARGET_LATEST, None)
    ]

    for poetry_project, command, target, version, min_poetry_version in test_cases:
        if min_poetry_version and poetry_version() < min_poetry_version:
            continue

        dry_run = subprocess.run(command, check=True, cwd=poetry_project, text=True, capture_output=True)
        assert any(is_install_line(target, version, line) for line in dry_run.stdout.split('\n'))


def test_poetry_dry_run_output_update(
    poetry_project_target_previous,
    poetry_project_target_previous_lock_latest,
):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency update has the expected format.
    """
    def is_update_line(target: str, line: str) -> bool:
        match = re.search(r"Updating (.*) \((.*)\)", line.strip())
        return match is not None and match.group(1) == target and "Skipped" not in line

    test_cases = [
        (poetry_project_target_previous, ["poetry", "add", "--dry-run", f"{TARGET}=={TARGET_LATEST}"], None),
        (poetry_project_target_previous_lock_latest, ["poetry", "install", "--dry-run"], None),
        (poetry_project_target_previous_lock_latest, ["poetry", "sync", "--dry-run"], POETRY_V2),
        (poetry_project_target_previous_lock_latest, ["poetry", "update", "--dry-run"], None),
    ]

    for poetry_project, command, min_poetry_version in test_cases:
        if min_poetry_version and poetry_version() < min_poetry_version:
            continue

        dry_run = subprocess.run(command, check=True, cwd=poetry_project, text=True, capture_output=True)
        assert any(is_update_line(TARGET, line) for line in dry_run.stdout.split('\n'))


def test_poetry_dry_run_output_downgrade(
    poetry_project_target_latest,
    poetry_project_target_latest_lock_previous,
):
    """
    Tests that a dry-run of an installish Poetry command that results in a
    dependency downgrade has the expected format.
    """
    def is_downgrade_line(target: str, line: str) -> bool:
        match = re.search(r"(Updating|Downgrading) (.*) \((.*)\)", line.strip())
        return match is not None and match.group(2) == target and "Skipped" not in line

    test_cases = [
        (poetry_project_target_latest, ["poetry", "add", "--dry-run", f"{TARGET}=={TARGET_PREVIOUS}"], None),
        (poetry_project_target_latest_lock_previous, ["poetry", "install", "--dry-run"], None),
        (poetry_project_target_latest_lock_previous, ["poetry", "sync", "--dry-run"], POETRY_V2),
        (poetry_project_target_latest_lock_previous, ["poetry", "update", "--dry-run"], None),
    ]

    for poetry_project, command, min_poetry_version in test_cases:
        if min_poetry_version and poetry_version() < min_poetry_version:
            continue

        dry_run = subprocess.run(command, check=True, cwd=poetry_project, text=True, capture_output=True)
        assert any(is_downgrade_line(TARGET, line) for line in dry_run.stdout.split('\n'))


def poetry_show(project_dir: str) -> str:
    """
    Get the current state of packages installed via Poetry.
    """
    poetry_show = subprocess.run(["poetry", "show"], check=True, cwd=project_dir, text=True, capture_output=True)
    return poetry_show.stdout.lower()


def poetry_version() -> Optional[version.Version]:
    """
    Get the version number of the active Poetry executable if it has the required
    format, otherwise return `None`.
    """
    try:
        poetry_version = subprocess.run(["poetry", "--version"], check=True, text=True, capture_output=True)
        match = re.search(r"Poetry \(version (.*)\)", poetry_version.stdout)
        return version.parse(match.group(1)) if match else None
    except Exception:
        return None
