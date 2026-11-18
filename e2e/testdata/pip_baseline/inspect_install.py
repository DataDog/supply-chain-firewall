import importlib
import importlib.metadata
import json
import sys

path, name, module = sys.argv[1:]
distributions = list(importlib.metadata.distributions(path=[path]))
matching = [d for d in distributions if d.metadata['Name'].lower() == name.lower()]
result = {'present': bool(matching), 'version': '', 'imported': False}
if matching:
    result['version'] = matching[0].version
    sys.path.insert(0, path)
    imported = importlib.import_module(module)
    if not imported.__file__.startswith(path + '/'):
        raise RuntimeError('import escaped isolated install directory')
    result['imported'] = True
print(json.dumps(result))
