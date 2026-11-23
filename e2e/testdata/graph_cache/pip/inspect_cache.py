import hashlib
import json
import os
import sys
from pip._vendor.cachecontrol.controller import CacheController
from pip._vendor import msgpack

MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = MAX_BODY_BYTES + 1024 * 1024


def read_bounded(path, limit):
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
    except FileNotFoundError:
        return None
    if len(data) > limit:
        raise RuntimeError("cached metadata or body too large")
    return data


root, *urls = sys.argv[1:]
result = {}
for url in urls:
    result[url] = {"present": False}
    key = hashlib.sha224(CacheController.cache_url(url).encode()).hexdigest()
    for directory in ("http", "http-v2"):
        # Decode the manager's on-disk layout, not the configured Python's
        # SafeFileCache API: its installed pip can be a different version.
        path = os.path.join(root, directory, *key[:5], key)
        data = read_bounded(path, MAX_METADATA_BYTES)
        if data is None:
            continue
        if not data.startswith(b"cc=4,"):
            raise RuntimeError("unsupported native cache serialization")
        response = msgpack.loads(data[5:], raw=False)["response"]
        body = response["body"]
        if directory == "http-v2":
            body = read_bounded(path + ".body", MAX_BODY_BYTES)
            if body is None:
                continue
        if not isinstance(body, bytes):
            raise RuntimeError("invalid cached response body")
        if len(body) > MAX_BODY_BYTES:
            raise RuntimeError("cached response too large")
        result[url] = {"present": True, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
print(json.dumps(result))
