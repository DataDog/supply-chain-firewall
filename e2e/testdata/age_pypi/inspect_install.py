# Read installed distribution metadata without enabling wheel startup hooks.
import importlib.metadata as metadata
import json
import re
import sys

def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()

matches = [
    distribution.version
    for distribution in metadata.distributions(path=[sys.argv[1]])
    if normalized(distribution.metadata["Name"]) == normalized(sys.argv[2])
]
if len(matches) > 1:
    raise RuntimeError("duplicate installed distributions")
print(json.dumps({"present": bool(matches), "version": matches[0] if matches else ""}))
