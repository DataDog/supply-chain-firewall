# Offline control for the registered two-invocation Poetry lifecycle scenario.
# Fake tools produce evidence only; they never access a package registry.
import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0])
args = sys.argv[1:]
project = Path.cwd()
if tool.name == "git":
    sys.exit(0)
if tool.name == "poetry":
    assert args == ["--no-interaction", "lock"]
    (project / "poetry.lock").write_text("bootstrap lock")
    sys.exit(0)
if tool.name == "python":
    if args[:2] == ["-m", "venv"]:
        launcher = Path(args[-1]) / "bin" / "python"
        launcher.parent.mkdir(parents=True)
        launcher.symlink_to(tool.resolve())
    else:
        assert args[0] == "-I"
        if project.parent.name == "subsequent" and (tool.resolve().parent / "fail-subsequent").exists():
            sys.exit(23)
        present = (project / ".installed").exists()
        print(json.dumps({"present": present, "version": "1.0" if present else "", "imported": present}))
    sys.exit(0)

assert tool.name == "scfw"
assert os.environ["SCFW_PROXY_ENABLED"] == "1"
blocked = (Path(os.environ["SCFW_HOME"]) / "list_verifier" / "e2e.yaml").exists()
outcome = "BLOCK" if blocked else "ALLOW"
operation = "add" if "add" in args else "install"
package = {"ecosystem": "PyPI", "package_name": "fixture", "package_version": "1.0", "outcome": outcome}
if blocked:
    package["findings"] = [{"verifier": "FindingsListVerifier", "severity": "CRITICAL", "text": "SCFW E2E exact-version finding"}]
policy = {"timestamp": "2026-01-01T00:00:00Z", "command": "poetry --no-interaction " + operation,
          "package_manager": "poetry", "executable": str(tool.parent / "poetry"),
          "repository": "https://example.invalid/scfw-e2e.git", "outcome": outcome, "packages": [package]}
Path(os.environ["SCFW_LOG_FILE"]).write_text(json.dumps(policy) + "\n")
print("running command through proxy\nstarted package manager proxy url=http://127.0.0.1:0", file=sys.stderr)
if not blocked:
    (project / ".installed").touch()
    if operation == "add":
        for name in ["pyproject.toml", "poetry.lock"]:
            path = project / name
            path.write_text(path.read_text() + "\n# added fixture")
    (Path(os.environ["POETRY_CACHE_DIR"]) / "fixture.whl").write_bytes(b"fixture wheel")
sys.exit(1 if blocked else 0)
