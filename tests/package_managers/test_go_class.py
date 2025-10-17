"""
Tests of Go`, the `PackageManager` subclass.
"""

import requests
from pathlib import Path
from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package
from scfw.package_managers.go import Go
import subprocess
import textwrap

from .test_go import GoProject, get_gopath, go_show, new_go_project

PACKAGE_MANAGER = Go()
"""
Fixed `PackageManager` to use across all tests.
"""

TARGET = "golang.org/x/xerrors"

LATEST_VERSION = requests.get(f"https://proxy.golang.org/{TARGET}/@latest", timeout=5).json()["Version"]


def test_go_command_would_install_remote(new_go_project):
    """
    Tests that `Go.resolve_install_targets()` correctly resolves installation
    targets for a variety of target specfications without installing anything.
    """
    test_cases = [
        ["go", "get", TARGET],
        ["go", "install", f"{TARGET}@latest"],
        ["go", "run", f"{TARGET}@latest"],
    ]

    base_go = GoProject(get_gopath(), "", {})
    global_init_state = base_go.get_go_dir_contents()

    local_init_state = go_show(new_go_project)

    for args in test_cases:
        targets = PACKAGE_MANAGER.resolve_install_targets(args)

        assert (
            len(targets) == 1
            and targets[0].ecosystem == ECOSYSTEM.Go
            and targets[0].name == TARGET
            and targets[0].version == LATEST_VERSION
        )
        assert go_show(new_go_project) == local_init_state
        assert base_go.get_go_dir_contents() == global_init_state


def test_go_command_would_install_local(new_go_project):
    """
    Tests that `Go.resolve_install_targets()` correctly resolves installation
    targets for a variety of commands that inspect the local project without
    installing anything.
    """
    test_cases = [
        ["go", "mod", "download"],
        ["go", "mod", "tidy"],
        ["go", "build", "."],
        ["go", "install", "."],
    ]

    base_go = GoProject(get_gopath(), "", {})
    global_init_state = base_go.get_go_dir_contents()

    _install_target(new_go_project)

    local_init_state = go_show(new_go_project)

    for args in test_cases:
        targets = PACKAGE_MANAGER.resolve_install_targets(args)

        assert (
            len(targets) == 1
            and targets[0].ecosystem == ECOSYSTEM.Go
            and targets[0].name == TARGET
            and targets[0].version == LATEST_VERSION
        )
        assert go_show(new_go_project) == local_init_state
        assert base_go.get_go_dir_contents() == global_init_state


def test_go_list_installed_packages(new_go_project):
    """
    Test that `Go.list_installed_packages` correctly parses `go` output.
    """
    target = Package(ECOSYSTEM.Go, TARGET, LATEST_VERSION)
    _install_target(new_go_project)
    assert [target] == PACKAGE_MANAGER.list_installed_packages()


def _install_target(project: GoProject):
    """
    Install the target package to the provided directory and write a dummy source file.
    """
    subprocess.run(["go", "get", f"{TARGET}@{LATEST_VERSION}"], check=True, cwd=project.directory, env=project.env)

    main = Path(project.directory, "main.go")
    with main.open(mode="w") as f:
        f.write(textwrap.dedent(f"""\
            package main

            import "{TARGET}"

            func main() {{
                _ = xerrors.New("error")
            }}"""))
