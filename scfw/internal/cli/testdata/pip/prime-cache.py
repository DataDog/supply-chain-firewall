import sys
from pip._internal.network.session import PipSession
with PipSession(cache=sys.argv[1]) as session:
    session.get(sys.argv[2],verify=sys.argv[3]).raise_for_status()
