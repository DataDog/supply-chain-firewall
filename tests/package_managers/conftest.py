"""
Pytest fixtures shared across all package manager tests.
"""

from .npm_fixtures import (  # noqa: F401
    empty_directory,
    new_npm_project,
    npm_project_aliased_dependency,
    npm_project_aliased_dependency_lockfile,
    npm_project_dangling_local_dependency,
    npm_project_dependency_latest,
    npm_project_dependency_latest_lockfile,
    npm_project_dependency_previous,
    npm_project_dependency_previous_lockfile,
    npm_project_installed_latest,
    npm_project_installed_previous,
    npm_project_local_dependency,
    npm_project_local_dependency_installed,
    npm_project_local_dependency_lockfile,
)
from .pip_fixtures import (  # noqa: F401
    new_pip_project,
    new_pip_project_installed,
    pip_project_local_dependency,
    pip_project_local_dependency_installed,
    pip_project_remote_dependency,
    pip_project_remote_dependency_installed,
)
from .poetry_fixtures import (  # noqa: F401
    new_poetry_project,
    poetry_project_lock_latest,
    poetry_project_no_lock,
    poetry_project_target_latest,
    poetry_project_target_latest_lock_previous,
    poetry_project_target_previous,
    poetry_project_target_previous_lock_latest,
)
