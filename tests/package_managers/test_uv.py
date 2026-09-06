"""
Tests of uv's command line behavior.
"""

import json
import re
import subprocess
from pathlib import Path

import packaging.version as version
import pytest

from scfw.package_managers.uv import Uv, TemporaryUvProject
from scfw.package import RemotePackageSource

UV_COMMAND_PREFIX = ["uv"]


def uv_pip_list() -> str:
    """
    Get the state of packages installed in an active environment via uv.
    """
    uv_command_list = UV_COMMAND_PREFIX + ["pip", "list", "--format", "freeze"]
    return subprocess.run(
        uv_command_list, check=True, text=True, capture_output=True
    ).stdout.lower()


def test_uv_version_output():
    """
    Test that `uv --version` has the required format and parses correctly.
    """
    uv_version = subprocess.run(
        UV_COMMAND_PREFIX + ["--version"], check=True, text=True, capture_output=True
    )
    match = re.match(r"^uv\s+(\S+)", uv_version.stdout.strip())
    assert match is not None
    parsed_version = version.parse(match.group(1))
    assert isinstance(parsed_version, version.Version)


def test_normalize_command(tmp_path: Path):
    """
    Test command normalization with invalid and valid commands.
    """
    dummy_exe = tmp_path / "uv"
    dummy_exe.touch()
    uv = Uv(executable=str(dummy_exe))

    assert uv._normalize_command(["uv", "sync"]) == [str(dummy_exe), "sync"]

    with pytest.raises(ValueError, match="Received empty uv command"):
        uv._normalize_command([])

    with pytest.raises(ValueError, match="Received invalid uv command line"):
        uv._normalize_command(["pip", "install"])


@pytest.mark.parametrize(
    "command_line",
    [
        UV_COMMAND_PREFIX + ["-V"],
        UV_COMMAND_PREFIX + ["--version"],
        UV_COMMAND_PREFIX + ["sync", "-h"],
        UV_COMMAND_PREFIX + ["sync", "--help"],
        UV_COMMAND_PREFIX + ["export", "-h"],
        UV_COMMAND_PREFIX + ["export", "--help"],
        UV_COMMAND_PREFIX + ["add", "-h"],
        UV_COMMAND_PREFIX + ["add", "--help"],
    ],
)
def test_uv_no_change_flags(command_line: list[str]):
    """
    Test that help and version flags execute without error
    and do not modify the active environment state.
    """
    init_state = uv_pip_list()
    subprocess.run(command_line, check=True)
    assert uv_pip_list() == init_state


@pytest.mark.parametrize(
    "command_line",
    [
        UV_COMMAND_PREFIX + ["export", "--format", "invalid_format_type"],
        UV_COMMAND_PREFIX + ["sync", "--invalid=flag-abc"],
        UV_COMMAND_PREFIX + ["add", "--invalid-option-xyz"],
    ],
)
def test_uv_command_error(command_line: list[str]):
    """
    Test that invalid commands or flags raise a CalledProcessError.
    """
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(command_line, check=True, capture_output=True)


def test_uv_export_requirements_format(tmp_path: Path):
    """
    Test that `uv export` produces a valid requirements.txt file output.
    """
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text(
        '[project]\nname = "test-pkg"\nversion = "0.1.0"\ndependencies = ["packaging>=20.0"]\n',
        encoding="utf-8",
    )

    requirements_file = tmp_path / "requirements.txt"
    export_cmd = UV_COMMAND_PREFIX + [
        "export",
        "--format",
        "requirements.txt",
        "--no-hashes",
        "--no-emit-workspace",
        "-o",
        str(requirements_file),
        "--project",
        str(tmp_path),
    ]

    subprocess.run(export_cmd, check=True, capture_output=True)

    assert requirements_file.is_file()

    file_content = requirements_file.read_text(encoding="utf-8")
    assert "packaging==" in file_content.lower()


def test_uv_pip_list_json_format():
    """
    Test that `uv pip list --format json` produces valid, parseable JSON metadata.
    """
    cmd = UV_COMMAND_PREFIX + ["pip", "list", "--format", "json"]
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)

    entries = json.loads(proc.stdout)
    assert isinstance(entries, list)

    if entries:
        first = entries[0]
        assert "name" in first
        assert "version" in first


def test_parse_uv_lock(tmp_path: Path):
    """
    Test parsing uv.lock files into Package objects under various source configurations.
    """
    lock_file = tmp_path / "uv.lock"

    assert TemporaryUvProject._parse_uv_lock(lock_file) == set()

    lock_content = """
version = 1
revision = 1

[[package]]
name = "my-root-pkg"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "wheel-pkg"
version = "1.2.3"
wheels = [
    { url = "https://custom.index/wheels/wheel_pkg-1.2.3-py3-none-any.whl" }
]

[[package]]
name = "sdist-pkg"
version = "2.0.0"
sdist = { url = "https://custom.index/sdist/sdist_pkg-2.0.0.tar.gz" }
"""
    lock_file.write_text(lock_content, encoding="utf-8")

    packages = TemporaryUvProject._parse_uv_lock(lock_file)

    assert len(packages) == 2

    pkg_map = {pkg.name: pkg for pkg in packages}

    assert pkg_map["wheel-pkg"].version == "1.2.3"
    assert isinstance(pkg_map["wheel-pkg"].source, RemotePackageSource)
    assert (
        pkg_map["wheel-pkg"].source.remote_source
        == "https://custom.index/wheels/wheel_pkg-1.2.3-py3-none-any.whl"
    )

    # Verify sdist source resolution
    assert pkg_map["sdist-pkg"].version == "2.0.0"
    assert isinstance(pkg_map["sdist-pkg"].source, RemotePackageSource)
    assert (
        pkg_map["sdist-pkg"].source.remote_source
        == "https://custom.index/sdist/sdist_pkg-2.0.0.tar.gz"
    )
