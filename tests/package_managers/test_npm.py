"""
Tests establishing the validity of Supply-Chain Firewall's assumptions about
npm's command-line options and behavior.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Optional

import packaging.version as version
import pytest

TEST_PACKAGE = "axios"
TEST_PACKAGE_LATEST = "1.13.0"
TEST_PACKAGE_PREVIOUS = "1.12.0"


@pytest.fixture
def empty_directory():
    """
    Initialize an empty directory.
    """
    tempdir = TemporaryDirectory()

    yield Path(tempdir.name)

    tempdir.cleanup()


@pytest.fixture
def new_npm_project():
    """
    Initialize a new npm project in an empty directory.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    _init_npm_project(tempdir_path)

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_test_package_latest():
    """
    Initialize an npm project with the latest version of `TEST_PACKAGE` installed.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    _init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_LATEST)],
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_test_package_previous_lockfile():
    """
    Initialize an npm project with the previous version of `TEST_PACKAGE` installed
    and with a `package-lock.json` file.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    _init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
    )

    yield tempdir_path

    tempdir.cleanup()


@pytest.fixture
def npm_project_test_package_previous_lockfile_modules():
    """
    Initialize an npm project with the previous version of `TEST_PACKAGE` installed
    and with a `package-lock.json` file and `node_modules/` directory.
    """
    tempdir = TemporaryDirectory()
    tempdir_path = Path(tempdir.name)
    _init_npm_project(
        tempdir_path,
        dependencies=[(TEST_PACKAGE, TEST_PACKAGE_PREVIOUS)],
        with_lockfile=True,
        with_node_modules=True,
    )

    yield tempdir_path

    tempdir.cleanup()


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


def test_npm_loglevel_override(empty_directory):
    """
    Test that we can override the log level setting included in an npm command,
    that is, that npm ignores all but the last instance of the `--loglevel` option.
    """
    command_line = [
        "npm", "--loglevel", "silent", "install", "--dry-run", TEST_PACKAGE, "--loglevel", "silly"
    ]
    silly_lines = _get_silly_log_lines(empty_directory, command_line)

    # We successfully overrode the `silent` log level and observe `silly` log lines
    assert silly_lines


def test_npm_log_line_format_place_dep(empty_directory):
    """
    Test that the `placeDep` log lines have the required format.
    """
    target_spec = f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"
    command_line = ["npm", "install", target_spec, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = _get_silly_log_lines(empty_directory, command_line)
    assert silly_lines

    # There are `placeDep` lines among the `silly` lines
    place_dep_lines = list(filter(lambda l: "placeDep" in l, silly_lines))
    assert place_dep_lines

    # The `placeDep` lines have the required format
    assert all(line.split()[2] == "placeDep" for line in place_dep_lines)
    assert all(re.fullmatch(r"@?(.+)@(.+)", line.split()[4]) for line in place_dep_lines)

    # One of the `placeDep` lines is for our test package
    assert any(line.split()[4] == target_spec for line in place_dep_lines)


def test_npm_log_line_format_add(empty_directory):
    """
    Test that the `ADD` log lines have the required format.
    """
    target_spec = f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"
    command_line = ["npm", "install", target_spec, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = _get_silly_log_lines(empty_directory, command_line)
    assert silly_lines

    # There are `ADD` lines among the `silly` lines
    add_lines = list(filter(lambda l: "ADD" in l, silly_lines))
    assert add_lines

    # The `ADD` lines have the required format
    assert all(line.split()[2] == "ADD" for line in add_lines)
    assert all(line.split()[3].startswith("node_modules/") for line in add_lines)

    # One of the `ADD` lines is for our test package
    assert any(line.split()[3] == f"node_modules/{TEST_PACKAGE}" for line in add_lines)


def test_npm_log_line_format_change(npm_project_test_package_previous_lockfile_modules):
    """
    Test that the `CHANGE` log lines have the required format.
    """
    target_spec = f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"
    command_line = ["npm", "install", target_spec, "--dry-run", "--loglevel", "silly"]

    # There are `silly` log lines for this command
    silly_lines = _get_silly_log_lines(npm_project_test_package_previous_lockfile_modules, command_line)
    assert silly_lines

    # There are `CHANGE` lines among the `silly` lines
    change_lines = list(filter(lambda l: "CHANGE" in l, silly_lines))
    assert change_lines

    # The `CHANGE` lines have the required format
    assert all(line.split()[2] == "CHANGE" for line in change_lines)
    assert all(line.split()[3].startswith("node_modules/") for line in change_lines)

    # One of the `CHANGE` lines is for our test package
    assert any(line.split()[3] == f"node_modules/{TEST_PACKAGE}" for line in change_lines)


def test_npm_install_package_lock_only_test_package_latest(npm_project_test_package_latest):
    """
    Test that the `--package-lock-only` option works as expected in an npm project
    with a specified dependency but no prior `package-lock.json` file.
    """
    _backend_test_npm_install_package_lock_only(npm_project_test_package_latest, ["npm", "install"])


def test_npm_install_package_lock_only_test_package_previous_lockfile(npm_project_test_package_previous_lockfile):
    """
    Test that the `--package-lock-only` option works as expected in an npm project
    with a specified dependency and a prior `package-lock.json` file.
    """
    _backend_test_npm_install_package_lock_only(
        npm_project_test_package_previous_lockfile,
        ["npm", "install", f"{TEST_PACKAGE}@{TEST_PACKAGE_LATEST}"]
    )


def test_npm_install_ignore_scripts(npm_project_test_package_latest):
    """
    Lorem ipsum dolor sit amet.
    """
    test_script_body = "This should never execute"
    scripts = {
        lifecycle: f"echo \"{test_script_body}\""
        for lifecycle in {"preinstall", "install", "postinstall"}
    }

    # Add lifecycle scripts to the package.json file
    package_json_path = npm_project_test_package_latest / "package.json"

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
        cwd=npm_project_test_package_latest
    )
    assert test_script_body in p.stdout

    # Check that the scripts do not run with `--ignore-scripts`
    p = subprocess.run(
        ["npm", "install", "--ignore-scripts"],
        check=True,
        text=True,
        capture_output=True,
        cwd=npm_project_test_package_latest
    )
    assert test_script_body not in p.stdout


@pytest.mark.parametrize(
        "command_line",
        [
            ["npm", "--version", "install", TEST_PACKAGE],
            ["npm", "install", "--version", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--version"],
            ["npm", "--version", "install", "--version", TEST_PACKAGE, "--version"],
            ["npm", "-h", "install", TEST_PACKAGE],
            ["npm", "install", "-h", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "-h"],
            ["npm", "-h", "install", "-h", TEST_PACKAGE, "-h"],
            ["npm", "--help", "install", TEST_PACKAGE],
            ["npm", "install", "--help", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--help"],
            ["npm", "--help", "install", "--help", TEST_PACKAGE, "--help"],
            ["npm", "--dry-run", "install", TEST_PACKAGE],
            ["npm", "install", "--dry-run", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--dry-run"],
            ["npm", "--dry-run", "install", "--dry-run", TEST_PACKAGE, "--dry-run"],
            ["npm", "--non-existent-option", "--version", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "-h", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "--help", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "--dry-run", "install", TEST_PACKAGE],
        ]
)
def test_options_prevent_install_empty_directory(empty_directory, command_line: list[str]):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in an empty directory.
    """
    _backend_test_no_change(empty_directory, command_line)


@pytest.mark.parametrize(
        "command_line",
        [
            ["npm", "--version", "install", TEST_PACKAGE],
            ["npm", "install", "--version", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--version"],
            ["npm", "--version", "install", "--version", TEST_PACKAGE, "--version"],
            ["npm", "-h", "install", TEST_PACKAGE],
            ["npm", "install", "-h", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "-h"],
            ["npm", "-h", "install", "-h", TEST_PACKAGE, "-h"],
            ["npm", "--help", "install", TEST_PACKAGE],
            ["npm", "install", "--help", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--help"],
            ["npm", "--help", "install", "--help", TEST_PACKAGE, "--help"],
            ["npm", "--dry-run", "install", TEST_PACKAGE],
            ["npm", "install", "--dry-run", TEST_PACKAGE],
            ["npm", "install", TEST_PACKAGE, "--dry-run"],
            ["npm", "--dry-run", "install", "--dry-run", TEST_PACKAGE, "--dry-run"],
            ["npm", "--non-existent-option", "--version", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "-h", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "--help", "install", TEST_PACKAGE],
            ["npm", "--non-existent-option", "--dry-run", "install", TEST_PACKAGE],
        ]
)
def test_options_prevent_install_new_npm_project(new_npm_project, command_line: list[str]):
    """
    Test that the `-h`/`--help` and `--dry-run` options prevent an `npm install`
    command from running in a new npm project.
    """
    _backend_test_no_change(new_npm_project, command_line)


def get_npm_project_state(path: Path) -> str:
    """
    Return the current state of installed packages in the npm project at `path`.
    """
    return subprocess.run(["npm", "list", "--all"], check=True, text=True, capture_output=True).stdout


def _backend_test_npm_install_package_lock_only(project: Path, command_line: list[str]):
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


def _backend_test_no_change(project: Path, command_line: list[str], should_error: bool = False):
    """
    Backend function for testing that running an npm command does not modify
    the project state and should or should not raise an error.
    """
    initial_state = get_npm_project_state(project)

    if should_error:
        with pytest.raises(subprocess.CalledProcessError):
            subprocess.run(command_line, check=True, cwd=project)
    else:
        subprocess.run(command_line, check=True, cwd=project)

    assert get_npm_project_state(project) == initial_state


def _get_silly_log_lines(project: Path, command_line: list[str]) -> list[str]:
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


def _init_npm_project(
    path: Path,
    dependencies: Optional[list[tuple[str, str]]] = None,
    with_lockfile: bool = False,
    with_node_modules: bool = False,
):
    """
    Initialize an npm project in `path` with the given `dependencies` and with or
    without the `package-lock.json` file and `node_modules/` directory present.

    Note that setting `with_lockfile=False` always results in the `node_modules/`
    directory being deleted, regardless of the value of `with_node_modules`.
    """
    subprocess.run(["npm", "init", "--yes"], check=True, text=True, capture_output=True, cwd=path)

    if not dependencies:
        return

    for package, version in dependencies:
        subprocess.run(
            ["npm", "install", f"{package}@{version}"],
            check=True,
            text=True,
            capture_output=True,
            cwd=path,
        )

    if not (with_node_modules and with_lockfile):
        shutil.rmtree(path / "node_modules")

    if not with_lockfile:
        os.remove(path / "package-lock.json")
