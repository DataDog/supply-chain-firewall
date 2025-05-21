"""
Tests of Go's command line behavior.
"""

import hashlib
import os
from pathlib import Path
import platform
import pytest
import subprocess
from tempfile import TemporaryDirectory

TEST_PROJECT_NAME = "foo"


class GoProject:
    """
    A representation of a Go project and its local environment.
    """
    def __init__(self, go_dir: str, directory: str, env: dict):
        self.go_dir = go_dir
        self.directory = directory
        self.env = env


    def get_go_dir_contents(self) -> str:
        """
        List the contents in the go directory.

        Note that this only looks at the name and path of the filesm ignoring
        their actual contents!
        """
        h = hashlib.new("md5")
        for root, _, files in os.walk(self.go_dir):
            r = Path(root)
            for name in files:
                h.update(bytes(r / name))
        return h.hexdigest()


@pytest.fixture
def new_go_project():
    """
    Initialize a clean Go project for use in testing and set it as the current directory
    for the duration of the test.
    """
    with TemporaryDirectory() as tmpdir:
        go_dir, env = _init_go_env(tmpdir)

        project_dir = Path(tmpdir) / "project"
        project_dir.mkdir(mode=0o750)

        original_dir = os.getcwd()

        _init_go_project(project_dir, env, TEST_PROJECT_NAME)
        os.chdir(project_dir)

        yield GoProject(go_dir, project_dir, env)

        os.chdir(original_dir)


def test_go_no_change(new_go_project):
    """
    Test that certain `go` commands relied on by Supply-Chain Firewall
    not to error or modify the local installation state indeed have these properties.
    """
    def _test_go_no_change(project: GoProject, base_go: GoProject, local_init_state: str, global_init_state: str, command: list) -> bool:
        """
        Tests that a given Poetry command does not encounter any errors and does not
        modify the local installation state when run in the context of a given project.
        """
        # 'go * -h' exits with 2.
        help_command = subprocess.run(command, check=False, cwd=project.directory, env=project.env)
        assert help_command.returncode == 2
        return go_show(project) == local_init_state and base_go.get_go_dir_contents() == global_init_state

    test_cases = []
    for command in ["build", "generate", "get", "install", "mod", "run"]:
        for param in ["-h", "-help"]:
            test_cases.append(["go", command, param])

    base_go = GoProject(get_gopath(), "", {})
    global_init_state = base_go.get_go_dir_contents()

    local_init_state = go_show(new_go_project)

    assert all(_test_go_no_change(new_go_project, base_go, local_init_state, global_init_state, command) for command in test_cases)


def go_show(project: GoProject) -> str:
    """
    Get the current state of packages installed via go.
    """
    go_show = subprocess.run(
        ["go", "list", "-m", "all"],
        check=True,
        cwd=project.directory,
        env=project.env,
        text=True,
        capture_output=True,
    )
    return go_show.stdout.lower()


def get_gopath() -> str:
    """
    Retrieve the default path where go install packages.
    """
    gopath = subprocess.run(["go", "env", "GOPATH"], check=True, text=True, capture_output=True)
    return gopath.stdout.strip()


def _init_go_env(directory) -> (Path, dict):
    """
    Initialize a fresh Go environment in `directory` and return both the path
    used by go and the environment variables that should be provided to
    subprocess to access it.
    """
    separator = ":"
    if platform.system() == "Windows":
        separator = ";"

    base_dir = Path(directory) / "go"
    base_dir.mkdir(mode=0o750)

    go_dir = base_dir / "go"
    go_dir.mkdir(mode=0o750)

    cache_dir = base_dir / "cache"
    cache_dir.mkdir(mode=0o750)

    mod_cache_dir = base_dir / "mod_cache"
    mod_cache_dir.mkdir(mode=0o750)

    gopath = get_gopath()

    env = os.environ.copy()
    env['GOPATH'] = f"{go_dir}{separator}{gopath}"
    env['GOCACHE'] = str(cache_dir)
    env['GOMODCACHE'] = str(mod_cache_dir)

    return base_dir, env


def _init_go_project(directory, env, name, dependencies = None):
    """
    Initialize a fresh Go project in `directory` with the given `dependencies`.
    """
    subprocess.run(["go", "mod", "init", name], check=True, cwd=directory, env=env)

    if dependencies:
        for package, version in dependencies:
            subprocess.run(["go", "get", f"{package}@{version}"], check=True, cwd=directory, env=env)
