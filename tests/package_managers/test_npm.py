"""
Tests establishing the validity of Supply-Chain Firewall's assumptions about
npm's command-line options and behavior.
"""

import itertools
import json
import os
from pathlib import Path
import re
import subprocess

import packaging.version as version
import pytest

from .npm_fixtures import *

PREVENT_INSTALL_TEST_CASES = list(
    itertools.product(
        [
            ["npm", "--version", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", "--version", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--version"],
            ["npm", "--version", "install", "--version", TEST_PACKAGE_LATEST_SPEC, "--version"],
            ["npm", "-h", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", "-h", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "-h"],
            ["npm", "-h", "install", "-h", TEST_PACKAGE_LATEST_SPEC, "-h"],
            ["npm", "--help", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", "--help", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--help"],
            ["npm", "--help", "install", "--help", TEST_PACKAGE_LATEST_SPEC, "--help"],
            ["npm", "--dry-run", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", "--dry-run", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--dry-run"],
            ["npm", "--dry-run", "install", "--dry-run", TEST_PACKAGE_LATEST_SPEC, "--dry-run"],
            ["npm", "--non-existent-option", "--version", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "--non-existent-option", "-h", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "--non-existent-option", "--help", "install", TEST_PACKAGE_LATEST_SPEC],
            ["npm", "--non-existent-option", "--dry-run", "install", TEST_PACKAGE_LATEST_SPEC],
        ],
        {TEST_PACKAGE_LATEST_SPEC},
    )
)


def test_npm_version_output():
    """
    Test that `npm --version` has the required format.
    """
    version_str = subprocess.run(["npm", "--version"], check=True, text=True, capture_output=True)
    version.parse(version_str.stdout.strip())


def test_npm_prefix_output(new_npm_project):
    """
    Test that the `npm prefix` command exists and has the expected behavior.
    """
    def get_npm_prefix(path: Path) -> Path:
        npm_prefix = subprocess.run(
            ["npm", "prefix"],
            check=True,
            text=True,
            capture_output=True,
            cwd=path,
        )
        return Path(npm_prefix.stdout.strip())

    # The conversions via `os.path.realpath()` are needed to account for a
    # macOS-specific discrepancy in which the temporary directories are under
    # `/private/var` but report being under only `/var`
    project_realpath = os.path.realpath(new_npm_project)

    assert os.path.realpath(get_npm_prefix(new_npm_project)) == project_realpath

    # Make a subdirectory and rerun the experiment from within
    subdirectory = new_npm_project / "foo"
    subdirectory.mkdir()

    assert os.path.realpath(get_npm_prefix(subdirectory)) == project_realpath

    # Now create an npm project in the subdirectory and check that the prefix changes
    init_npm_project(subdirectory)
    assert os.path.realpath(get_npm_prefix(subdirectory)) == os.path.realpath(subdirectory)


def test_npm_loglevel_override(empty_directory):
    """
    Test that we can override the log level setting included in an npm command,
    that is, that npm ignores all but the last instance of the `--loglevel` option.
    """
    command_line = [
        "npm", "--loglevel", "silent", "install", "--dry-run", TEST_PACKAGE, "--loglevel", "silly"
    ]
    silly_lines = get_silly_log_lines(empty_directory, command_line)

    # We successfully overrode the `silent` log level and observe `silly` log lines
    assert silly_lines


def test_npm_log_line_format_place_dep(empty_directory):
    """
    Test that the `placeDep` log lines have the required format.
    """
    command_line = ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = get_silly_log_lines(empty_directory, command_line)
    assert silly_lines

    # There are `placeDep` lines among the `silly` lines
    place_dep_lines = list(filter(lambda l: "placeDep" in l, silly_lines))
    assert place_dep_lines

    # The `placeDep` lines have the required format
    assert all(line.split()[2] == "placeDep" for line in place_dep_lines)
    assert all(re.fullmatch(r"@?(.+)@(.+)", line.split()[4]) for line in place_dep_lines)

    # One of the `placeDep` lines is for our test package
    assert any(line.split()[4] == TEST_PACKAGE_LATEST_SPEC for line in place_dep_lines)


def test_npm_log_line_format_add(empty_directory):
    """
    Test that the `ADD` log lines have the required format.
    """
    command_line = ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = get_silly_log_lines(empty_directory, command_line)
    assert silly_lines

    # There are `ADD` lines among the `silly` lines
    add_lines = list(filter(lambda l: "ADD" in l, silly_lines))
    assert add_lines

    # The `ADD` lines have the required format
    assert all(line.split()[2] == "ADD" for line in add_lines)
    assert all(line.split()[3].startswith("node_modules/") for line in add_lines)

    # One of the `ADD` lines is for our test package
    assert any(line.split()[3] == f"node_modules/{TEST_PACKAGE}" for line in add_lines)


def test_npm_log_line_format_change(npm_project_installed_previous):
    """
    Test that the `CHANGE` log lines have the required format.
    """
    command_line = ["npm", "install", TEST_PACKAGE_LATEST_SPEC, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = get_silly_log_lines(npm_project_installed_previous, command_line)
    assert silly_lines

    # There are `CHANGE` lines among the `silly` lines
    change_lines = list(filter(lambda l: "CHANGE" in l, silly_lines))
    assert change_lines

    # The `CHANGE` lines have the required format
    assert all(line.split()[2] == "CHANGE" for line in change_lines)
    assert all(line.split()[3].startswith("node_modules/") for line in change_lines)

    # One of the `CHANGE` lines is for our test package
    assert any(line.split()[3] == f"node_modules/{TEST_PACKAGE}" for line in change_lines)


def test_npm_install_package_lock_only_dependency_latest(npm_project_dependency_latest):
    """
    Test that the `--package-lock-only` option works as expected in an npm project
    with a specified dependency but no prior `package-lock.json` file.
    """
    backend_test_npm_install_package_lock_only(npm_project_dependency_latest, ["npm", "install"])


def test_npm_install_package_lock_only_dependency_previous_lockfile(
    npm_project_dependency_previous_lockfile,
):
    """
    Test that the `--package-lock-only` option works as expected in an npm project
    with a specified dependency and a prior `package-lock.json` file.
    """
    backend_test_npm_install_package_lock_only(
        npm_project_dependency_previous_lockfile,
        ["npm", "install", TEST_PACKAGE_LATEST_SPEC]
    )


def test_npm_install_ignore_scripts(npm_project_dependency_latest):
    """
    Test that the `--ignore-scripts` option works as expected.
    """
    test_script_body = "This should never execute"
    scripts = {
        lifecycle: f"echo \"{test_script_body}\""
        for lifecycle in {"preinstall", "install", "postinstall"}
    }

    # Add lifecycle scripts to the package.json file
    package_json_path = npm_project_dependency_latest / "package.json"

    with open(package_json_path) as f:
        package_json = json.load(f)

    package_json["scripts"] = scripts

    with open(package_json_path, 'w') as f:
        json.dump(package_json, f, indent=4)

    # Check that the scripts do run normally
    p = subprocess.run(
        ["npm", "install"],
        check=True,
        text=True,
        capture_output=True,
        cwd=npm_project_dependency_latest,
    )
    assert test_script_body in p.stdout

    # Check that the scripts do not run with `--ignore-scripts`
    p = subprocess.run(
        ["npm", "install", "--ignore-scripts"],
        check=True,
        text=True,
        capture_output=True,
        cwd=npm_project_dependency_latest,
    )
    assert test_script_body not in p.stdout


@pytest.mark.parametrize("command_line, test_target", PREVENT_INSTALL_TEST_CASES)
def test_options_prevent_install_empty_directory(
    empty_directory,
    command_line: list[str],
    test_target: str,
):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in an empty directory.
    """
    backend_test_no_install(empty_directory, command_line, test_target)


@pytest.mark.parametrize("command_line, test_target", PREVENT_INSTALL_TEST_CASES)
def test_options_prevent_install_new_npm_project(
    new_npm_project,
    command_line: list[str],
    test_target: str,
):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in a new npm project.
    """
    backend_test_no_install(new_npm_project, command_line, test_target)


@pytest.mark.parametrize("command_line, test_target", PREVENT_INSTALL_TEST_CASES)
def test_options_prevent_install_dependency_previous(
    npm_project_dependency_previous,
    command_line: list[str],
    test_target: str,
):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS`
    specified as a dependency but not installed.
    """
    backend_test_no_install(npm_project_dependency_previous, command_line, test_target)


@pytest.mark.parametrize("command_line, test_target", PREVENT_INSTALL_TEST_CASES)
def test_options_prevent_install_dependency_previous_lockfile(
    npm_project_dependency_previous_lockfile,
    command_line: list[str],
    test_target: str,
):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS`
    specified as a dependency and present in the lockfile but not installed.
    """
    backend_test_no_install(npm_project_dependency_previous_lockfile, command_line, test_target)


@pytest.mark.parametrize("command_line, test_target", PREVENT_INSTALL_TEST_CASES)
def test_options_prevent_install_installed_previous(
    npm_project_installed_previous,
    command_line: list[str],
    test_target: str,
):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install` command
    from running in an npm project with `TEST_PACKAGE@TEST_PACKAGE_PREVIOUS` installed.
    """
    backend_test_no_install(
        npm_project_installed_previous,
        command_line,
        test_target,
    )


def backend_test_npm_install_package_lock_only(project: Path, command_line: list[str]):
    """
    Backend function for testing that the `--package-lock-only` option of the
    `npm install` command works as expected.
    """
    subprocess.run(
        command_line + ["--package-lock-only"],
        check=True,
        text=True,
        capture_output=True,
        cwd=project,
    )

    package_json_path = project / "package.json"
    lockfile_path = project / "package-lock.json"
    node_modules_path = project / "node_modules/"

    assert package_json_path.is_file()
    assert lockfile_path.is_file()
    assert not node_modules_path.exists()


def backend_test_no_install(
    project: Path,
    command_line: list[str],
    test_target: str,
):
    """
    Backend function for testing that an `npm install` command does not install
    `test_target` in `project` after being executed.
    """
    def check_lockfile(lockfile_path: Path, package_name: str, version: str):
        with open(lockfile_path) as f:
            lockfile = json.load(f)
        if (entry := lockfile["packages"].get(f"node_modules/{package_name}")):
            assert entry["version"] != version

    def check_node_modules(node_modules_path: Path, package_name: str, version: str):
        module_path = node_modules_path / package_name
        if not module_path.is_dir():
            return

        package_json_path = module_path / "package.json"
        with open(package_json_path) as f:
            package_json = json.load(f)
        assert package_json["version"] != version

    package_name, sep, version = test_target.rpartition('@')
    assert (package_name and sep)

    lockfile_path = project / "package-lock.json"
    if (has_lockfile := lockfile_path.is_file()):
        check_lockfile(lockfile_path, package_name, version)

    node_modules_path = project / "node_modules"
    if (has_node_modules := node_modules_path.is_dir()):
        check_node_modules(node_modules_path, package_name, version)

    subprocess.run(command_line, check=True, cwd=project)

    if has_lockfile:
        check_lockfile(lockfile_path, package_name, version)
    else:
        assert not lockfile_path.is_file()

    if has_node_modules:
        check_node_modules(node_modules_path, package_name, version)
    else:
        assert not node_modules_path.is_dir()


def get_silly_log_lines(project: Path, command_line: list[str]) -> list[str]:
    """
    Return the `silly` log lines output, if any, from running the given `command_line`
    in the given `project`.

    If there are `silly` lines, ensure they have the expected format before returning.
    """
    log_output = subprocess.run(
        command_line,
        check=True,
        text=True,
        capture_output=True,
        cwd=project,
    )

    silly_lines = list(
        filter(lambda l: l.startswith("npm sill"), log_output.stderr.strip().split('\n'))
    )

    # The `silly` log lines all have the expected format
    assert (
        all(line.split()[1] == "sill" for line in silly_lines)
        or all(line.split()[1] == "silly" for line in silly_lines)
    )

    return silly_lines
