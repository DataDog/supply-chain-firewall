import json
import os
import sys

with open(os.environ["SCFW_TEST_CHILD_OUTPUT"], "w") as output:
    json.dump({"arguments": sys.argv[1:], "directory": os.getcwd()}, output)
