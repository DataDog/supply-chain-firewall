"""
Provides a class for spinning up ephemeral Go environments to run commands in.
"""

import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Optional, Type
from typing_extensions import Self


class TempGoEnvironment(TemporaryDirectory):
    """
    Prepares a temporary environment in which `go` commands may be executed without affecting
    the user's global environment.

    This may be used as a context manager. On completion of the context the temporary
    environment will be removed from the filesystem, alongside any changes that may have
    been made to the current project.

    Alternatively, when done with the environment, you may call `cleanup()` to remove the
    temporary environment.
    """
    def __init__(self, executable: str):
        """
        Initialize a new `TempGoEnvironment`.

        Args:
            executable: A `str` path in the local filesystem to the `go` executable to use.
        """
        def make_subdir(parent: Path, child: str) -> Path:
            subdir = parent / child
            subdir.mkdir(mode=0o750)
            return subdir

        def get_gomod_path(executable: str) -> Optional[Path]:
            gomod_command = [executable, "env", "GOMOD"]
            gomod = subprocess.run(gomod_command, check=True, text=True, capture_output=True)
            gomod_path = gomod.stdout.strip()
            if not gomod_path or gomod_path in {"/dev/null", "NUL"}:
                return None
            return Path(gomod_path).absolute()

        def get_gosum_path(gomod_path: Optional[Path]) -> Optional[Path]:
            # If go.sum exists, it is in the same directory as go.mod
            return gomod_path.parent / "go.sum" if gomod_path else None

        def get_gopath(executable: str) -> str:
            gopath_command = [executable, "env", "GOPATH"]
            return subprocess.run(gopath_command, check=True, text=True, capture_output=True).stdout.strip()

        TemporaryDirectory.__init__(self)
        self._tmp_dir = Path(self.name)

        self._cached_gomod_path = None
        self._cached_gosum_path = None
        self._remove_sum_file = False

        self._executable = executable
        self._gomod_path = get_gomod_path(executable)
        self._gosum_path = get_gosum_path(self._gomod_path)

        # Ephemeral dry-run subdirectory
        self._dry_run_dir = make_subdir(self._tmp_dir, "dry_run")

        # Ephemeral cache subdirectory
        self._cache_dir = make_subdir(self._tmp_dir, "cache")

        # Ephemeral module cache subdirectory
        self._mod_cache_dir = make_subdir(self._tmp_dir, "mod_cache")

        # Ephemeral module download subdirectory
        self._go_dir = make_subdir(self._tmp_dir, "go")

        # Go searches all directories listed in GOPATH to find source code but
        # new packages are always downloaded into the first directory in the list
        self._gopath = f"{self._go_dir}:{get_gopath(executable)}"

        # Override Go-specific environment variables so that all package
        # downloading and caching occurs within the disposable `TempGoEnvironment`
        self._env = os.environ.copy()
        self._env['GOCACHE'] = str(self._cache_dir)
        self._env['GOMODCACHE'] = str(self._mod_cache_dir)
        self._env['GOPATH'] = self._gopath

    def __enter__(self) -> Self:
        """
        Convert the `TempGoEnvironment` to a context manager.

        Returns:
            The object itself managing the temporary environment.
        """
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        """
        Clear the temporary environment and undo any changes made to the current project.
        """
        self.cleanup()

    def duplicate_go_mod(self):
        """
        Duplicate the `go.mod` and `go.sum` files in the nearest ancestor directory.

        On `cleanup()` (and hence context manager exit), these files are recovered,
        in case they were modified.
        """
        if self._gomod_path and self._gomod_path.is_file():
            self._cached_gomod_path = self._tmp_dir / "go.mod"
            shutil.copy(self._gomod_path, self._cached_gomod_path)
        else:
            raise RuntimeError("Failed to find a 'go.mod' file to operate on")

        if self._gosum_path and self._gosum_path.is_file():
            self._cached_gosum_path = self._tmp_dir / "go.sum"
            shutil.copy(self._gosum_path, self._cached_gosum_path)
        else:
            self._remove_sum_file = True

    def run(self, args: list[str], local: bool = False) -> subprocess.CompletedProcess:
        """
        Execute a `go` command within the temporary environment.

        Args:
            args: The list of arguments passed to `go`.

        Returns:
            A representation of the finished proccess.
        """
        return subprocess.run(
            [self._executable] + args,
            cwd=None if local else self._dry_run_dir,
            env=self._env,
            check=True,
            text=True,
            capture_output=True,
        )

    def cleanup(self):
        """
        Clear the temporary environment and undo any changes made to the current project.
        """
        if self._gomod_path and self._cached_gomod_path:
            shutil.copy(self._cached_gomod_path, self._gomod_path)

        if self._gosum_path:
            if self._cached_gosum_path:
                shutil.copy(self._cached_gosum_path, self._gosum_path)
            elif self._gosum_path.is_file() and self._remove_sum_file:
                os.remove(self._gosum_path)

        TemporaryDirectory.cleanup(self)
