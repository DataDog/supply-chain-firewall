import hashlib
import json
import os
import sys
from pip._internal.network.cache import SafeFileCache
from pip._vendor.cachecontrol.controller import CacheController
from pip._vendor import msgpack

root, *urls = sys.argv[1:]
result = {}
for url in urls:
    result[url] = {"present": False}
    for directory in ("http", "http-v2"):
        cache = SafeFileCache(os.path.join(root, directory))
        key = CacheController.cache_url(url)
        data = cache.get(key)
        if data is None:
            continue
        if not data.startswith(b"cc=4,"):
            raise RuntimeError("unsupported native cache serialization")
        response = msgpack.loads(data[5:], raw=False)["response"]
        body = response["body"]
        if hasattr(cache, "get_body"):
            stream = cache.get_body(key)
            if stream is not None:
                with stream:
                    body = stream.read(16 * 1024 * 1024 + 1)
        if len(body) > 16 * 1024 * 1024:
            raise RuntimeError("cached response too large")
        result[url] = {"present": True, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
print(json.dumps(result))
