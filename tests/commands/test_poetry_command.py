"""
Tests of `PoetryCommand`.
"""

import pytest

from scfw.commands.poetry_command import PoetryCommand
from scfw.ecosystem import ECOSYSTEM

from .test_poetry import (
    TARGET, new_poetry_project, poetry_project_target_latest, poetry_project_target_previous,
    poetry_show, target_latest, target_previous, target_releases
)

TARGET_REPO = f"https://github.com/{TARGET}/py-tree-sitter"


@pytest.mark.parametrize(
    "poetry_project, target_spec, target_name, target_version",
    [
        ("new_poetry_project", "{}", TARGET, None),
        ("new_poetry_project", "{}@latest", TARGET, None),
        ("new_poetry_project", "{}=={}", TARGET, "target_latest"),
        ("new_poetry_project", "git+{}", TARGET_REPO, None),
        ("new_poetry_project", "git+{}#v{}", TARGET_REPO, "target_latest"),
        ("new_poetry_project", "git+{}.git", TARGET_REPO, None),
        ("new_poetry_project", "git+{}.git#v{}", TARGET_REPO, "target_latest"),
        ("new_poetry_project", "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, "target_latest"),
        ("poetry_project_target_latest", "{}=={}", TARGET, "target_previous"),
        ("poetry_project_target_latest", "git+{}#v{}", TARGET_REPO, "target_previous"),
        ("poetry_project_target_latest", "git+{}.git#v{}", TARGET_REPO, "target_previous"),
        ("poetry_project_target_latest", "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, "target_previous"),
        ("poetry_project_target_previous", "{}=={}", TARGET, "target_latest"),
        ("poetry_project_target_previous", "git+{}#v{}", TARGET_REPO, "target_latest"),
        ("poetry_project_target_previous", "git+{}.git#v{}", TARGET_REPO, "target_latest"),
        ("poetry_project_target_previous", "{}/archive/refs/tags/v{}.tar.gz", TARGET_REPO, "target_latest"),
    ]
)
def test_poetry_command_would_install(
    new_poetry_project,
    poetry_project_target_latest,
    poetry_project_target_previous,
    target_latest,
    target_previous,
    poetry_project,
    target_spec,
    target_name,
    target_version,
):
    """
    Tests that `PoetryCommand.would_install()` correctly resolves installation
    targets for a variety of target specfications without installing anything.
    """
    if poetry_project == "new_poetry_project":
        poetry_project = new_poetry_project
    elif poetry_project == "poetry_project_target_latest":
        poetry_project = poetry_project_target_latest
    elif poetry_project == "poetry_project_target_previous":
        poetry_project = poetry_project_target_previous

    if target_version is None:
        target_spec = target_spec.format(target_name)
        target_version = target_latest
    else:
        if target_version == "target_latest":
            target_version = target_latest
        elif target_version == "target_previous":
            target_version = target_previous

        target_spec = target_spec.format(target_name, target_version)

    init_install_state = poetry_show(poetry_project)

    command = PoetryCommand(["poetry", "add", "--directory", poetry_project, target_spec])
    targets = command.would_install()

    assert (
        len(targets) == 1
        and targets[0].ecosystem == ECOSYSTEM.PyPI
        and targets[0].package == TARGET
        and targets[0].version == target_version
    )
    assert poetry_show(poetry_project) == init_install_state
