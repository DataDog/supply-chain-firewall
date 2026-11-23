import importlib.metadata as metadata
import json
import sys

try:
    version = metadata.version(sys.argv[1])
except metadata.PackageNotFoundError:
    version = ""
print(json.dumps({"present": bool(version), "version": version}))
