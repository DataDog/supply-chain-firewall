import os,signal,subprocess,sys,time
root=os.environ['SCFW_TEST_SIGNAL_DIR']
child=subprocess.Popen([sys.executable,'-c', '''import os,signal,time
root=os.environ['SCFW_TEST_SIGNAL_DIR']
def stop(signum, frame):
    open(root+'/child-signal','w').write(str(signum))
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)
open(root+'/child-ready','w').close()
while True: time.sleep(.01)
'''])
def stop(signum, frame):
    open(root+'/parent-signal','w').write(str(signum))
    child.wait(timeout=2)
    raise SystemExit(42)
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)
while not os.path.exists(root+'/child-ready'): time.sleep(.01)
open(root+'/ready','w').close()
while True: time.sleep(.01)
