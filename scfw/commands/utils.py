"""
Provides common utilities for package manager commands.
"""

import subprocess
from typing import Optional


def resolve_executable(executable: str) -> Optional[str]:
    """
    Resolve the given executable to its local filesystem path.

    Args:
        executable: The name of the executable to be resolved.

    Returns:
        The local filesystem path to the given executable in the current environment
        or `None` if the executable cannot be resolved.

    Raises:
        RuntimeError: Failed to resolve the given executable.
    """
    try:
        path = subprocess.run(["which", executable], check=True, text=True, capture_output=True).stdout.strip()
        return path if len(path) > 0 else None

    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to resolve executable '{executable}'")
