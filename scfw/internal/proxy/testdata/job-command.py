import os,signal,subprocess,sys,time
root=os.environ['SCFW_TEST_JOB_DIR']
for name in ('child-ready','child-term'):
    try: os.unlink(root+'/'+name)
    except FileNotFoundError: pass
child=subprocess.Popen([sys.executable,'-c', """import os,signal,time
root=os.environ['SCFW_TEST_JOB_DIR']
def terminated(signum,frame):
    open(root+'/child-term','w').close()
    raise SystemExit(0)
signal.signal(signal.SIGTERM,terminated)
open(root+'/child-ready','w').close()
while True: time.sleep(.05)
"""])
def terminated(signum,frame):
    child.wait(timeout=2)
    raise SystemExit(0)
signal.signal(signal.SIGTERM,terminated)
while not os.path.exists(root+'/child-ready'): time.sleep(.01)
def resumed(signum,frame):
    open(root+'/resumed','w').close()
signal.signal(signal.SIGCONT,resumed)
open(root+'/child-group','w').write(str(os.getpgrp()))
open(root+'/ready','w').close()
for line in sys.stdin: pass
