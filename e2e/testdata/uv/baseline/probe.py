import importlib.metadata as metadata
import json
import os
import sys

keys = ["HTTPS_PROXY", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "UV_CONFIG_FILE", "SCFW_E2E_SENTINEL"]
package = os.environ.get("SCFW_E2E_EXPECT_PACKAGE")
version = metadata.version(package) if package else ""
if package:
    assert version == os.environ["SCFW_E2E_EXPECT_VERSION"]
print(json.dumps({"args": sys.argv[1:], "stdin": sys.stdin.read(), "env": {key: os.environ.get(key) for key in keys}, "package_version": version}))
sys.exit(7)
