import json
import os
import signal
import sys
import time

state = {'args': sys.argv[1:], 'proxy': os.environ['HTTPS_PROXY'],
         'ca': os.environ['SSL_CERT_FILE'], 'git_ca': os.environ['GIT_SSL_CAINFO']}
if os.environ['SCFW_UV_TEST_MODE'] == 'passthrough':
    state.update(stdin=sys.stdin.read(), config=os.environ['UV_CONFIG_FILE'],
                 git_config=os.environ['GIT_CONFIG_VALUE_0'])
with open(os.environ['SCFW_UV_TEST_RESULT'], 'w') as result:
    json.dump(state, result)

if os.environ['SCFW_UV_TEST_MODE'] == 'passthrough':
    sys.exit(0)

if os.environ['SCFW_UV_TEST_MODE'] == 'signal':
    def interrupted(signum, frame):
        sys.exit(42)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    with open(os.environ['SCFW_UV_TEST_RESULT'] + '.ready', 'w') as ready:
        ready.write('ready')
    while True:
        time.sleep(0.01)
else:
    sys.exit(23)
