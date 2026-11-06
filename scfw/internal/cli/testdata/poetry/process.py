import os
import sys

assert sys.argv[1:] == ["a value with spaces", "--opaque"]
assert sys.stdin.read() == "inherited stdin\n"
assert os.environ["SCFW_TEST_INHERITED"] == "unchanged"
assert os.environ["POETRY_HTTP_BASIC_PRIVATE_PASSWORD"] == "secret"
assert os.environ["GIT_CONFIG_VALUE_0"] == "inherited git value"
assert "GIT_SSL_NO_VERIFY" not in os.environ
assert os.path.isfile(os.environ["REQUESTS_CA_BUNDLE"])
assert os.environ["GIT_SSL_CAINFO"] == os.environ["REQUESTS_CA_BUNDLE"]
assert os.environ["SSL_CERT_FILE"] == os.environ["REQUESTS_CA_BUNDLE"]
assert os.environ["HTTP_PROXY"] == os.environ["HTTPS_PROXY"]
assert os.environ["HTTP_PROXY"].startswith("http://127.0.0.1:")
assert os.environ["NO_PROXY"] == ""
print("inherited stdout")
print("inherited stderr", file=sys.stderr)
sys.exit(17)
