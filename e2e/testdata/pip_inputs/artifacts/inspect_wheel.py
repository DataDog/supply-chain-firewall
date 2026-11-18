import email
import json
import sys
import zipfile

path, name, version = sys.argv[1:]
with zipfile.ZipFile(path) as wheel:
    metadata = [p for p in wheel.namelist() if p.endswith('.dist-info/METADATA')]
    if len(metadata) != 1:
        raise RuntimeError('expected one wheel distribution')
    info = email.message_from_bytes(wheel.read(metadata[0]))
    if info['Name'].lower() != name.lower() or info['Version'] != version:
        raise RuntimeError('built wheel identity differs from discovered sdist')
    print(json.dumps({'name': info['Name'], 'version': info['Version'], 'path': path}))
