import json
import os
import sys

if os.environ.get("SCFW_TEST_CHILD_URL"):
    import requests

    response = requests.get(
        os.environ["SCFW_TEST_CHILD_URL"],
        verify=os.environ["SCFW_TEST_CHILD_CA"],
        timeout=5,
    )
    response.raise_for_status()
    assert response.text == "Poetry run HTTPS response"

with open(os.environ["SCFW_TEST_CHILD_OUTPUT"], "w") as output:
    json.dump(
        {
            "arguments": sys.argv[1:],
            "directory": os.getcwd(),
            "environment": {
                key: os.environ.get(key)
                for key in os.environ.get("SCFW_TEST_CHILD_ENV_KEYS", "").split(",")
                if key
            },
        },
        output,
    )
