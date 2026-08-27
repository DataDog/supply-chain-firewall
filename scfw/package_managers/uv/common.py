"""
Provides common definitions related to uv.
"""

UV_LOCK = "uv.lock"
PYPROJECT_TOML = "pyproject.toml"
PYTHON_VERSION_FILE = ".python-version"

# uv add options that do consume the following argument
UV_ADD_VALUE_OPTIONS: set[str] = {
    "--group",
    "--optional",
    "--index",
    "--default-index",
    "--index-strategy",
    "--branch",
    "--tag",
    "--rev",
    "--subdirectory",
    "--python",
}

ALLOW_EXPORT_PREFIXES: tuple = (
    "--extra",
    "--all-extras",
    "--no-extra",
    "--group",
    "--only-group",
    "--no-group",
    "--all-groups",
    "--dev",
    "--no-dev",
)
