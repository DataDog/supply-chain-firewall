"""Read manager-generated locks; never resolve dependencies in the harness."""
import json
from pathlib import Path
import sys
import tomllib
from urllib.parse import urlsplit

manager, path, root, leaf = sys.argv[1:]
lock = tomllib.loads(Path(path).read_text())
nodes = []
for package in lock["package"]:
    if manager == "uv" and package["name"] == "scfw-graph-cache":
        assert package.get("source") == {"virtual": "."}, "unexpected local project source"
        assert package.get("dependencies") == [{"name": root}], "root is not the sole direct requirement"
        continue
    if manager == "poetry":
        assert not package.get("optional", False), "optional graph package"
        assert not package.get("source"), "non-default graph registry"
        files = {item["file"]: item["hash"].removeprefix("sha256:") for item in package["files"]}
        required = isinstance(package.get("dependencies", {}).get(leaf), str)
    else:
        assert package["source"] == {"registry": "https://pypi.org/simple"}, "unexpected graph registry"
        files = {Path(urlsplit(item["url"]).path).name: item["hash"].removeprefix("sha256:") for item in package.get("wheels", [])}
        required = {"name": leaf} in package.get("dependencies", [])
    nodes.append({"Name": package["name"], "Version": package["version"], "Files": files, "Required": required})
print(json.dumps(nodes))
