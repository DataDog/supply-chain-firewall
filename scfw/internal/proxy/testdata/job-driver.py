import errno,os,pty,select,shlex,signal,sys,time
root=os.environ['SCFW_TEST_JOB_DIR']
shell,master=pty.fork()
if shell==0:
    os.environ['PS1']='SCFW_JOB_PROMPT> '
    os.execv(sys.argv[1],[sys.argv[1],'--noprofile','--norc','-i'])
output=b''
def wait_for(predicate):
    global output
    deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        if predicate(): return
        readable,_,_=select.select([master],[],[],.05)
        if readable:
            try: data=os.read(master,65536)
            except OSError as error:
                if error.errno==errno.EIO: break
                raise
            if not data: break
            output+=data
    raise RuntimeError('interactive test timed out: '+output.decode(errors='replace'))
try:
    wait_for(lambda:b'SCFW_JOB_PROMPT> ' in output)
    output=b''
    command=shlex.quote(sys.argv[2])+' -test.run=^TestRunInteractiveJobControlHelper$\n'
    os.write(master,command.encode())
    wait_for(lambda:os.path.exists(root+'/ready'))
    os.write(master,b'\x1a')
    wait_for(lambda:b'Stopped' in output and b'SCFW_JOB_PROMPT> ' in output)
    os.write(master,b'fg\n')
    wait_for(lambda:os.path.exists(root+'/resumed'))
    output=b''
    os.write(master,b'\x03')
    wait_for(lambda:b'SCFW_JOB_PROMPT> ' in output)
    # A signal sent only to SCFW must also reach its build subprocesses.
    os.unlink(root+'/ready')
    output=b''
    os.write(master,command.encode())
    wait_for(lambda:os.path.exists(root+'/ready'))
    with open(root+'/wrapper') as source: wrapper=int(source.read())
    os.kill(wrapper,signal.SIGTERM)
    wait_for(lambda:b'SCFW_JOB_PROMPT> ' in output)
    if not os.path.exists(root+'/child-term'):
        raise RuntimeError('SIGTERM did not reach terminal build subprocess')
finally:
    for name in ('child-group','wrapper'):
        try:
            with open(root+'/'+name) as source: group=int(source.read())
            os.killpg(group,signal.SIGKILL)
        except (OSError,ValueError): pass
    try: os.killpg(shell,signal.SIGKILL)
    except OSError: pass
    os.close(master)
    os.waitpid(shell,0)
