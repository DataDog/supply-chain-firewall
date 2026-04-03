"""
Thorough tests for the Bun `PackageManager` implementation.
"""

import subprocess
from pathlib import Path

import pytest

import scfw.package_managers.bun as bun_module
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_manager import UnsupportedVersionError
from scfw.package_managers import get_package_manager
from scfw.package_managers.bun import Bun


class _FakeCompletedProcess:
    """
    Minimal stand-in for `subprocess.CompletedProcess`.
    """

    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


def _make_fake_bun_executable(
    directory: Path,
    *,
    version_output: str = "1.3.8+b64edcb49",
    default_exit_code: int = 0,
) -> Path:
    """
    Create a tiny executable script that behaves like `bun` for the parts we need.
    """
    executable = directory / "bun"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        f'  echo "{version_output}"\n'
        "  exit 0\n"
        "fi\n"
        f"exit {default_exit_code}\n"
    )
    executable.chmod(0o755)
    return executable


@pytest.fixture
def fake_bun(tmp_path: Path) -> Bun:
    """
    Provide a Bun instance backed by a fake local executable.
    """
    executable = _make_fake_bun_executable(tmp_path)
    return Bun(executable=str(executable))


def test_bun_name_and_ecosystem():
    """
    Test Bun identity metadata.
    """
    assert Bun.name() == "bun"
    assert Bun.ecosystem() == ECOSYSTEM.Bun


def test_get_package_manager_returns_bun(tmp_path: Path):
    """
    Test that the package-manager factory returns a Bun instance.
    """
    executable = _make_fake_bun_executable(tmp_path)
    package_manager = get_package_manager("bun", executable=str(executable))

    assert isinstance(package_manager, Bun)
    assert package_manager.name() == "bun"
    assert package_manager.ecosystem() == ECOSYSTEM.Bun


def test_bun_init_rejects_missing_executable(tmp_path: Path):
    """
    Test that Bun rejects a missing executable path.
    """
    with pytest.raises(RuntimeError, match="does not correspond to a regular file"):
        Bun(executable=str(tmp_path / "missing-bun"))


def test_bun_init_rejects_unsupported_version(tmp_path: Path):
    """
    Test that Bun rejects versions older than the minimum supported version.
    """
    executable = _make_fake_bun_executable(tmp_path, version_output="0.9.9")

    with pytest.raises(UnsupportedVersionError):
        Bun(executable=str(executable))


def test_bun_executable_property(fake_bun: Bun):
    """
    Test that Bun.executable() returns the configured executable path.
    """
    executable = fake_bun.executable()

    assert executable is not None
    assert Path(executable).is_file()


def test_bun_normalize_command(fake_bun: Bun):
    """
    Test that Bun normalizes command lines correctly.
    """
    normalized = fake_bun._normalize_command(["bun", "--version"])

    assert normalized[0] == fake_bun.executable()
    assert normalized[1:] == ["--version"]


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["npm", "--version"],
    ],
)
def test_bun_run_command_rejects_invalid_command(fake_bun: Bun, command: list[str]):
    """
    Test that Bun rejects invalid command lines.
    """
    with pytest.raises(ValueError):
        fake_bun.run_command(command)


def test_bun_run_command_returns_exit_code(tmp_path: Path):
    """
    Test that Bun.run_command() returns the underlying process exit code.
    """
    executable = _make_fake_bun_executable(tmp_path, default_exit_code=7)
    package_manager = Bun(executable=str(executable))

    assert package_manager.run_command(["bun", "--not-a-real-command"]) == 7


@pytest.mark.parametrize(
    "command_line",
    [
        ["bun", "add", "chalk@5.3.0"],
        ["bun", "a", "chalk@5.3.0"],
        ["bun", "install", "chalk@5.3.0"],
        ["bun", "i", "chalk@5.3.0"],
    ],
)
def test_bun_resolve_install_targets_add_variants(
    fake_bun: Bun,
    monkeypatch,
    command_line: list[str],
):
    """
    Test that Bun resolves package targets for the install/add aliases it supports.
    """
    expected_packages = [Package(ECOSYSTEM.Bun, "chalk", "5.3.0")]

    def fake_run(
        command, check=False, text=False, capture_output=False, cwd=None, **kwargs
    ):
        assert command[0] == fake_bun.executable()
        assert command[1:] == command_line[1:] + ["--dry-run"]
        return _FakeCompletedProcess(stdout="installed chalk@5.3.0\n[1.00ms] done\n")

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.resolve_install_targets(command_line) == expected_packages


@pytest.mark.parametrize(
    "command_line",
    [
        ["bun", "add", "chalk@5.3.0", "--help"],
        ["bun", "add", "chalk@5.3.0", "-h"],
        ["bun", "install", "chalk@5.3.0", "--help"],
        ["bun", "install", "chalk@5.3.0", "-h"],
    ],
)
def test_bun_resolve_install_targets_help_flags_return_empty(
    fake_bun: Bun,
    monkeypatch,
    command_line: list[str],
):
    """
    Test that Bun does not resolve install targets when help is requested.
    """

    def fake_run(*args, **kwargs):
        raise AssertionError("subprocess.run should not be called for help flags")

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.resolve_install_targets(command_line) == []


@pytest.mark.parametrize(
    "command_line",
    [
        ["bun", "run", "test"],
        ["bun", "test"],
        ["bun", "--version"],
    ],
)
def test_bun_resolve_install_targets_non_install_command_returns_empty(
    fake_bun: Bun,
    monkeypatch,
    command_line: list[str],
):
    """
    Test that Bun returns an empty target list for non-install commands.
    """

    def fake_run(*args, **kwargs):
        raise AssertionError(
            "subprocess.run should not be called for non-install commands"
        )

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.resolve_install_targets(command_line) == []


def test_bun_resolve_install_targets_subprocess_failure_returns_empty(
    fake_bun: Bun,
    monkeypatch,
):
    """
    Test that Bun swallows dry-run failures and returns an empty list.
    """

    def fake_run(
        command, check=False, text=False, capture_output=False, cwd=None, **kwargs
    ):
        raise subprocess.CalledProcessError(returncode=1, cmd=command)

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.resolve_install_targets(["bun", "add", "chalk@5.3.0"]) == []


def test_bun_resolve_install_targets_rejects_invalid_command(fake_bun: Bun):
    """
    Test that Bun rejects invalid resolve commands.
    """
    with pytest.raises(ValueError):
        fake_bun.resolve_install_targets([])

    with pytest.raises(ValueError):
        fake_bun.resolve_install_targets(["npm", "install", "chalk@5.3.0"])


def test_bun_list_installed_packages_parses_tree_output(
    fake_bun: Bun,
    monkeypatch,
):
    """
    Test that Bun parses tree-formatted `bun list --all` output.
    """
    expected_packages = [
        Package(ECOSYSTEM.Bun, "react", "18.3.0"),
        Package(ECOSYSTEM.Bun, "js-tokens", "4.0.0"),
        Package(ECOSYSTEM.Bun, "loose-envify", "1.4.0"),
    ]

    def fake_run(
        command, check=False, text=False, capture_output=False, cwd=None, **kwargs
    ):
        assert command[0] == fake_bun.executable()
        assert command[1:] == ["list", "--all"]
        return _FakeCompletedProcess(
            stdout=(
                "react@18.3.0\n"
                "├── js-tokens@4.0.0\n"
                "└── loose-envify@1.4.0\n"
                "[2.00ms] done\n"
            )
        )

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.list_installed_packages() == expected_packages


def test_bun_list_installed_packages_parses_flat_output(
    fake_bun: Bun,
    monkeypatch,
):
    """
    Test that Bun parses flat `bun list --all` output.
    """
    expected_packages = [
        Package(ECOSYSTEM.Bun, "left-pad", "1.3.0"),
        Package(ECOSYSTEM.Bun, "is-number", "7.0.0"),
    ]

    def fake_run(
        command, check=False, text=False, capture_output=False, cwd=None, **kwargs
    ):
        assert command[0] == fake_bun.executable()
        assert command[1:] == ["list", "--all"]
        return _FakeCompletedProcess(stdout="left-pad@1.3.0\nis-number@7.0.0\n")

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    assert fake_bun.list_installed_packages() == expected_packages


def test_bun_list_installed_packages_raises_on_failure(
    fake_bun: Bun,
    monkeypatch,
):
    """
    Test that Bun raises a runtime error when `bun list` fails.
    """

    def fake_run(
        command, check=False, text=False, capture_output=False, cwd=None, **kwargs
    ):
        raise subprocess.CalledProcessError(returncode=1, cmd=command)

    monkeypatch.setattr(bun_module.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="Failed to list bun installed packages"):
        fake_bun.list_installed_packages()
