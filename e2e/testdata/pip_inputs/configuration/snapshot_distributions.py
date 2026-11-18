import hashlib
import importlib.metadata
import json
import pathlib
import sys

site, *names = sys.argv[1:]
wanted = {name.lower() for name in names}
state = {}
for distribution in importlib.metadata.distributions(path=[site]):
    if distribution.metadata['Name'].lower() not in wanted:
        continue
    files = {}
    for entry in distribution.files or []:
        path = pathlib.Path(distribution.locate_file(entry))
        files[str(entry)] = hashlib.sha256(path.read_bytes()).hexdigest()
    state[distribution.metadata['Name']] = {'version': distribution.version, 'files': files}
if len(state) != len(wanted):
    raise RuntimeError('missing existing distribution before/after upgrade')
print(json.dumps(state, sort_keys=True))
