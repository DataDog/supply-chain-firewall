import json
import os
import sys

keys = [
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "GIT_SSL_CAINFO", "SCFW_E2E_POETRY_PROBE",
]
print(json.dumps({"argv": sys.argv[1:], "stdin": sys.stdin.read(),
                  "environment": {key: os.environ.get(key) for key in keys}},
                 sort_keys=True))
print("Poetry direct child stderr", file=sys.stderr)
sys.exit(7)
