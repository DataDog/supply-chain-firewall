"""
Tests of pip's command line behavior.
"""

import json
import os
import subprocess
import sys
import tempfile
from typing import Optional

import packaging.version as version
import pytest

from .pip_fixtures import *

PIP_COMMAND_PREFIX = [sys.executable, "-m", "pip"]


def pip_list() -> str:
    """
    Get the current state of packages installed via pip.
    """
    pip_list_command = PIP_COMMAND_PREFIX + ["list", "--format", "freeze"]
    return subprocess.run(pip_list_command, check=True, text=True, capture_output=True).stdout.lower()


def select_test_install_target(installed_packages: str) -> str:
    """
    Select a test target that is not in the given installed packages output.

    This allows us to be certain when testing that nothing was installed in a dry-run.
    """
    def read_top_pypi_packages() -> set[str]:
        test_dir = os.path.dirname(os.path.realpath(__file__, strict=True))
        top_packages_file = os.path.join(test_dir, f"top_pypi_packages.txt")
        with open(top_packages_file) as f:
            return set(f.read().split())

    try:
        top_packages = read_top_pypi_packages()
        while (choice := top_packages.pop()) in installed_packages:
            pass
        return choice

    except KeyError:
        raise RuntimeError("Unable to select a target package for testing")


INIT_PIP_STATE = pip_list()
"""
Caches the pip installation state before running any tests.
"""

TEST_TARGET = select_test_install_target(INIT_PIP_STATE)
"""
A fresh (not currently installed) package target to use for testing.
"""


def test_pip_version_output():
    """
    Test that `pip --version` has the required format.
    """
    pip_version = subprocess.run(PIP_COMMAND_PREFIX + ["--version"], check=True, text=True, capture_output=True)
    version_str = pip_version.stdout.split()[1]
    version.parse(version_str)


@pytest.mark.parametrize(
        "command_line",
        [
            PIP_COMMAND_PREFIX + ["-h", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["--help", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "-h", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--help", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", TEST_TARGET, "--dry-run"]
        ]
)
def test_pip_no_change(command_line: list[str]):
    """
    Backend function for testing that a `pip` command does not encounter any
    errors and does not modify the local `pip` installation state.
    """
    subprocess.run(command_line, check=True)
    assert pip_list() == INIT_PIP_STATE


@pytest.mark.parametrize(
        "command_line",
        [
            PIP_COMMAND_PREFIX + ["--dry-run", "install", TEST_TARGET],
            PIP_COMMAND_PREFIX + ["install", "--dry-run", "!!!a_nonexistent_p@ckage_name"]
        ]
)
def test_pip_no_change_error(command_line: list[str]):
    """
    Backend function for testing that a `pip` command raises an error and
    does not modify the local `pip` installation state.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True)
    assert pip_list() == INIT_PIP_STATE


@pytest.mark.parametrize(
        "should_fail,verbose_options",
        [
            (True,  ["-v"]),
            (False, ["-q"]),
            (True,  ["-v", "-q"]),
            (False, ["-v", "-qq"]),
            (True,  ["-vv", "-qq"]),
            (False, ["-vv", "-qqq"]),
            (True,  ["-vvv", "-qqq"]),
            (False, ["-vvv", "-qqqq"]),
            (True,  ["-vvvv", "-qqqq"]),
            (False, ["-vvvv", "-qqqqq"]),
        ]
)
def test_pip_install_report_verbose_json(should_fail: bool, verbose_options: list[str]):
    """
    Test to determine how many `-q/--quiet` options are needed to override various
    numbers of `-v/--verbose` options (no effect after three), measured by whether
    the report JSON parses successfully when read from stdout.
    """
    command_line = (
        PIP_COMMAND_PREFIX + ["install", "--dry-run", "--report", "-", TEST_TARGET] + verbose_options
    )
    p = subprocess.run(command_line, check=True, text=True, capture_output=True)
    if should_fail:
        with pytest.raises(json.JSONDecodeError):
            json.loads(p.stdout)
    else:
        json.loads(p.stdout)


def test_pip_install_report_override():
    """
    Test that all but the last instance of the `--report` option in the command
    line are ignored by `pip`.
    """
    with tempfile.NamedTemporaryFile() as tmpfile:
        command_line = (
            PIP_COMMAND_PREFIX +
            ["--quiet", "install", "--dry-run", "--report", tmpfile.name, TEST_TARGET, "--report", "-"]
        )
        p = subprocess.run(command_line, check=True, text=True, capture_output=True)
        # The report went to stdout and has installation targets
        assert p.stdout
        report = json.loads(p.stdout)
        assert report.get("install")
        # Nothing was written to the temporary file
        assert tmpfile.read() == b''


def test_pip_install_report_format_local(new_pip_project):
    """
    Test that the dry-run report has the expected format for a local package target.
    """
    _test_pip_install_report_format(
        str(new_pip_project),
        TEST_PACKAGE_NAME,
        TEST_PACKAGE_VERSION,
        new_pip_project,
    )


def test_pip_install_report_format_remote():
    """
    Test that the dry-run report has the expected format for a remote package target.
    """
    package_name = "tree-sitter"
    package_version = "0.24.0"

    _test_pip_install_report_format(
        f"{package_name}=={package_version}",
        package_name,
        package_version,
        None,
    )


def _test_pip_install_report_format(
    target_spec: str,
    package_name: str,
    package_version: str,
    local_package_source: Optional[Path],
):
    """
    Backend function for testing that the dry-run report has the expected format.
    """
    command_line = (
        PIP_COMMAND_PREFIX +
        ["install", target_spec, "--dry-run", "-qqqqq", "--report", "-"]
    )
    p = subprocess.run(command_line, check=True, text=True, capture_output=True)
    install_reports = json.loads(p.stdout).get("install", [])

    assert len(install_reports) == 1
    install_report = install_reports[0]

    metadata = install_report.get("metadata")
    assert metadata
    name = metadata.get("name")
    assert name == package_name
    version = metadata.get("version")
    assert version == package_version

    download_info = install_report.get("download_info")
    assert download_info
    url = download_info.get("url")

    if local_package_source:
        assert url == f"file://{local_package_source}"
    else:
        assert url.startswith("https://files.pythonhosted.org")


def test_pip_inspect_matches_pip_list_new_pip_project(new_pip_project):
    """
    Test that `pip inspect` and `pip list` output match in an uninstalled `pip` project.
    """
    backend_test_pip_inspect_matches_pip_list(new_pip_project)


def test_pip_inspect_matches_pip_list_new_pip_project_installed(new_pip_project_installed):
    """
    Test that `pip inspect` and `pip list` output match in an installed `pip` project.
    """
    backend_test_pip_inspect_matches_pip_list(new_pip_project_installed)


def test_pip_inspect_matches_pip_list_pip_project_remote_dependency(pip_project_remote_dependency):
    """
    Test that `pip inspect` and `pip list` output match in an uninstalled `pip` project
    with a remote dependency from PyPI.
    """
    backend_test_pip_inspect_matches_pip_list(pip_project_remote_dependency)


def test_pip_inspect_matches_pip_list_pip_project_remote_dependency_installed(pip_project_remote_dependency_installed):
    """
    Test that `pip inspect` and `pip list` output match in an installed `pip` project
    with a remote dependency from PyPI.
    """
    backend_test_pip_inspect_matches_pip_list(pip_project_remote_dependency_installed)


def test_pip_inspect_matches_pip_list_pip_project_local_dependency(pip_project_local_dependency):
    """
    Test that `pip inspect` and `pip list` output match in an uninstalled `pip` project
    with a local dependency.
    """
    backend_test_pip_inspect_matches_pip_list(pip_project_local_dependency)


def test_pip_inspect_matches_pip_list_pip_project_local_dependency_installed(pip_project_local_dependency_installed):
    """
    Test that `pip inspect` and `pip list` output match in an installed `pip` project
    with a local dependency.
    """
    backend_test_pip_inspect_matches_pip_list(pip_project_local_dependency_installed)


def test_pip_inspect_registry_package_no_direct_url(pip_project_remote_dependency_installed):
    """
    Test that a package installed from the PyPI registry has no `direct_url` entry in
    `pip inspect` output. When `direct_url` is absent, `Pip.list_installed_packages`
    treats this as a registry install and uses the canonical PyPI project page URL as a
    stand-in `RemotePackageSource`.
    """
    venv_pip = pip_project_remote_dependency_installed / "venv" / "bin" / "pip"

    result = subprocess.run([venv_pip, "inspect"], check=True, text=True, capture_output=True)
    installed = json.loads(result.stdout).get("installed", [])

    matching = [
        e for e in installed
        if e.get("metadata", {}).get("name", "").lower() == REMOTE_PACKAGE_NAME
    ]
    assert len(matching) == 1
    assert "direct_url" not in matching[0]


def test_pip_inspect_local_package_direct_url_format(pip_project_local_dependency_installed):
    """
    Test that a locally-installed package has a `direct_url` entry in `pip inspect`
    output whose `url` field uses the `file://` scheme with an absolute path (PEP 610).
    The implementation strips the `file://` prefix and passes the remainder to `Path()`,
    relying on this path being absolute so that `LocalPackageSource` resolves correctly.
    """
    venv_pip = pip_project_local_dependency_installed / "venv" / "bin" / "pip"

    result = subprocess.run([venv_pip, "inspect"], check=True, text=True, capture_output=True)
    installed = json.loads(result.stdout).get("installed", [])

    matching = [
        e for e in installed
        if e.get("metadata", {}).get("name", "").lower() == LOCAL_PACKAGE_NAME
    ]
    assert len(matching) == 1

    direct_url = matching[0].get("direct_url")
    assert direct_url is not None

    url = direct_url.get("url", "")
    assert url.startswith("file://")
    assert Path(url[len("file://"):]).is_absolute()


def backend_test_pip_inspect_matches_pip_list(project_dir: Path):
    """
    Backend function for testing that `pip inspect` and `pip list` output match.
    """
    venv_pip = project_dir / "venv" / "bin" / "pip"

    pip_inspect = subprocess.run(
        [venv_pip, "inspect"], check=True, text=True, capture_output=True
    )
    inspect_packages = {
        (e["metadata"]["name"].lower(), e["metadata"]["version"])
        for e in json.loads(pip_inspect.stdout.strip()).get("installed", [])
    }

    pip_list = subprocess.run(
        [venv_pip, "list", "--format", "json"], check=True, text=True, capture_output=True
    )
    list_packages = {
        (pkg["name"].lower(), pkg["version"])
        for pkg in json.loads(pip_list.stdout.strip())
    }

    assert inspect_packages == list_packages
