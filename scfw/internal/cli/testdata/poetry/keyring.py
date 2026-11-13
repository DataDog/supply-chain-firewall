import os
from keyring.backend import KeyringBackend


class TestKeyring(KeyringBackend):
    priority = 1

    def get_password(self, service, username):
        if service.endswith("private") and username == "private":
            with open(os.environ["SCFW_TEST_KEYRING_READ"], "a") as reads:
                reads.write("read\n")
            return "secret"
        return None

    def set_password(self, service, username, password):
        raise AssertionError("SCFW must not change keyring credentials")

    def delete_password(self, service, username):
        raise AssertionError("SCFW must not delete keyring credentials")
