"""Retain cache inventories and distinguish metadata from reusable artifacts."""
import hashlib
import json
from pathlib import Path
import sys

manager, directory, *projects = sys.argv[1:]
cache = Path(directory)
files = []
artifacts = {name: False for name in projects}
metadata = False
for path in sorted(cache.rglob("*")):
    if not path.is_file():
        continue
    relative = str(path.relative_to(cache))
    files.append({"path": relative, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    metadata |= "/repositories/" in "/" + relative if manager == "poetry" else relative.startswith("simple-v")
    for project in projects:
        normalized = project.replace("-", "_")
        if manager == "poetry":
            artifacts[project] |= path.name.startswith(normalized + "-") and path.suffix == ".whl"
        else:
            artifacts[project] |= path.name == "RECORD" and path.parent.name.startswith(normalized + "-") and path.parent.name.endswith(".dist-info")
print(json.dumps({"Metadata": metadata, "Artifacts": artifacts, "Files": files}))
