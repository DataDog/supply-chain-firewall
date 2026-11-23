import importlib
import importlib.metadata
import json
from pathlib import Path
import sys

name, module = sys.argv[1:]
matching = [d for d in importlib.metadata.distributions()
            if d.metadata["Name"].lower() == name.lower()]
result = {"present": bool(matching), "version": "", "imported": False}
if matching:
    result["version"] = matching[0].version
    imported = importlib.import_module(module)
    if not Path(imported.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("import escaped isolated project environment")
    result["imported"] = True
print(json.dumps(result))
