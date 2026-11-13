import os
import sys

assert sys.argv[1:] == ["a value with spaces", "--opaque"]
assert sys.stdin.read() == "inherited stdin\n"
assert os.environ["SCFW_TEST_INHERITED"] == "unchanged"
assert os.environ["POETRY_HTTP_BASIC_PRIVATE_PASSWORD"] == "secret"
assert os.environ["GIT_CONFIG_VALUE_0"] == "inherited git value"
assert os.environ["GIT_CONFIG_COUNT"] == "1"
assert os.environ["GIT_SSL_NO_VERIFY"] == "1"
assert os.environ["REQUESTS_CA_BUNDLE"] == "/original/requests.pem"
assert os.environ["GIT_SSL_CAINFO"] == "/original/git.pem"
assert os.environ["SSL_CERT_FILE"] == "/original/ssl.pem"
assert os.environ["HTTP_PROXY"] == "http://original.example:8080"
assert os.environ["NO_PROXY"] == "original.example"
print("inherited stdout")
print("inherited stderr", file=sys.stderr)
sys.exit(17)
