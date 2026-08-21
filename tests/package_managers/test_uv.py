"""
Tests of uv's command line behavior.
"""

import json
import re
from pathlib import Path
import subprocess

from scfw.package_managers.uv import Uv

import packaging.version as version
import pytest

UV_COMMAND_PREFIX = ["uv"]


def uv_pip_list() -> str:
    """
    Get the state of packages installed in an active environment via uv.
    """
    uv_command_list = UV_COMMAND_PREFIX + ["pip", "list", "--format", "freeze"]
    return subprocess.run(uv_command_list, check=True, text=True, capture_output=True).stdout.lower()


def test_uv_version_output():
    """
    Tests that `uv --version` has the required format and parses correctly.
    """
    uv_version = subprocess.run(UV_COMMAND_PREFIX + ["--version"], check=True, text=True, capture_output=True)
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
    ],
)
def test_uv_no_change_flags(command_line: list[str]):
    """
    Tests that help and version flags execute without error
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
    ],
)
def test_uv_command_error(command_line: list[str]):
    """
    Tests that invalid commands or flags raise a CalledProcessError.
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
        "--no-emit-project",
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
    Tests that `uv pip list --format json` produces valid, parseable JSON metadata.
    """
    cmd = UV_COMMAND_PREFIX + ["pip", "list", "--format", "json"]
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)

    entries = json.loads(proc.stdout)
    assert isinstance(entries, list)

    if entries:
        first = entries[0]
        assert "name" in first
        assert "version" in first
