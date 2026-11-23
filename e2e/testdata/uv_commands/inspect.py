"""Read output metadata without importing installed packages or startup hooks."""
import email
import importlib.metadata
import json
from pathlib import Path
import sys
import tomllib
import zipfile

root = Path(sys.argv[1])
project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
state = {"version": project["version"], "dependencies": project["dependencies"],
         "lock": {}, "lock_artifacts": [], "installed": {}, "compiled": "",
         "wheels": {}, "venv": (root / ".venv" / "pyvenv.cfg").exists()}

def normalize(name):
    return name.lower().replace("_", "-").replace(".", "-")

lock = root / "uv.lock"
if lock.exists():
    for package in tomllib.loads(lock.read_text()).get("package", []):
        state["lock"][normalize(package["name"])] = package["version"]
        for artifact in package.get("wheels", []) + [package.get("sdist", {})]:
            digest = artifact.get("hash", "")
            if digest.startswith("sha256:"):
                state["lock_artifacts"].append(digest.removeprefix("sha256:"))
state["lock_artifacts"].sort()
for directory in (root / ".venv" / "lib").glob("python*/site-packages"):
    for dist in importlib.metadata.distributions(path=[str(directory)]):
        state["installed"][normalize(dist.metadata["Name"])] = dist.version
compiled = root / "compiled.txt"
if compiled.exists():
    state["compiled"] = compiled.read_text()
for wheel in (root / "dist").glob("*.whl"):
    with zipfile.ZipFile(wheel) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata) == 1, metadata
        headers = email.message_from_bytes(archive.read(metadata[0]))
        state["wheels"][normalize(headers["Name"])] = headers["Version"]
print(json.dumps(state, sort_keys=True))
