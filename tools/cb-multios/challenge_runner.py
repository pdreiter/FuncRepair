#!/usr/bin/env python3

import os
import re
import signal
import subprocess as sp
from time import time, sleep
import threading
import codecs

from common import IS_DARWIN, IS_LINUX, IS_WINDOWS, try_delete

def setNB(fd):
    import fcntl
    flags=fcntl.fcntl(fd,fcntl.F_GETFL)
    flags=flags|os.O_NONBLOCK
    fcntl.fcntl(fd,fcntl.F_SETFL,flags)


# Path to crash dumps in windows
if IS_WINDOWS:
    # NOTE: These may need to be changed depending on your setup
    DUMP_DIR = os.path.join(os.path.expandvars('%LOCALAPPDATA%'), 'CrashDumps')
    CDB_PATH = 'C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/cdb.exe'


def run(challenges, timeout, seed, logfunc, enable_fixes=False):
    """ Challenge launcher for replay services

    This will setup fds for all challenges according to:
    https://github.com/CyberGrandChallenge/cgc-release-documentation/blob/master/newsletter/ipc.md

    Args:
        challenges (list): List of absolute paths to all challenges to launch
        timeout (int): Maximum time in seconds a challenge is allowed to run for
        seed (str): Hex encoded seed for libcgc random
        logfunc ((str) -> None): Replayer log function used for reporting results

    Returns:
        (list): all processes that were started
    """
    cb_env = {'seed': seed}  # Environment variables for all challenges
	
    if os.environ.get('LD_BIND_NOW',None) is not None:
	    cb_env['LD_BIND_NOW']='1'

    if enable_fixes or (os.environ.get('ENABLE_FIXES',None) is not None):
	    cb_env['ENABLE_FIXES']='1'

    # This is the first fd after all of the challenges
    last_fd = 2 * len(challenges) + 3

    # Create all challenge fds
    if len(challenges) > 1:
        # Close fds where the pipes will be placed
        os.closerange(3, last_fd)

        new_fd = 3  # stderr + 1
        for i in range(len(challenges)):
            # Create a pipe for every running binary
            rpipe, wpipe = os.pipe()

            # The write end of the pipe needs to be at the lower fd, so it *may* get dup'd over the read end
            # Preemptively dup the read fd here to avoid the issue
            rpipe_tmp = os.dup(rpipe)
            pipe_fds = [wpipe, rpipe_tmp]

            # Duplicate the pipe ends to the correct fds if needed
            for fd in pipe_fds:
                if fd != new_fd:
                    os.dup2(fd, new_fd)
                new_fd += 1

            # Done with the temporary dup
            os.close(rpipe_tmp)

        # None of the above file descriptors will actually be inherited on Windows
        # Prepare the environment so libcgc can regenerate this setup
        # with the inherited HANDLEs
        if IS_WINDOWS:
            import msvcrt

            # Store the number of pipes that need to be set up
            numpipes = len(challenges) * 2  # Pipe pair for each
            cb_env['PIPE_COUNT'] = str(numpipes)

            # Store the HANDLE for each of the pipes
            for i in range(len(challenges) * 2):
                cb_env['PIPE_{}'.format(i)] = str(msvcrt.get_osfhandle(3 + i))  # First pipe is at 3

    # Start all challenges
    # Launch the main binary first
    import shlex
    mainchal, otherchals = shlex.split(challenges[0]), challenges[1:]
    logfunc("mainchal: "+str(mainchal))
    logfunc("# otherchals: "+str(len(otherchals)))
    procs = [sp.Popen(mainchal, env=cb_env, stdin=sp.PIPE,
                      stdout=sp.PIPE, stderr=sp.PIPE,bufsize=1)]
    # Any others should be launched with the same std i/o pipes
    # as the main binary
    if len(otherchals) > 0:
        main = procs[0]
        procs += [sp.Popen(shlex.split(c), env=cb_env, stdin=main.stdin,
                           stdout=main.stdout, stderr=main.stderr,bufsize=1) for c in otherchals]

    # Start a watcher to report results when the challenges exit
    watcher = threading.Thread(target=chal_watcher, args=(challenges, procs, timeout, logfunc))
    watcher.setDaemon(True)
    watcher.start()

    return procs, watcher

def chal_watcher(paths, procs, timeout, log):
    # Continue until any of the processes die

    # Wait until any process exits
    start = time()
    while time() - start < timeout \
            and all(proc.poll() is None for proc in procs):
        sleep(0.1)

    # Give the others a chance to exit
    while time() - start < timeout \
            and any(proc.poll() is None for proc in procs):
        sleep(0.1)

    # Kill any remaining processes
    for i,proc in enumerate(procs):
        if proc.poll() is None:
            log("[DEBUG] Process {} did not terminate".format(i))
            log("[DEBUG] Process type: "+str(type(proc)))
            #proc.send_signal(signal.SIGKILL)
            proc.terminate()
            proc.wait()

    # Close all of the ipc pipes
    if len(procs) > 1:
        last_fd = 2 * len(procs) + 3
        os.closerange(3, last_fd)

    # If any of the processes crashed, print out crash info
    for path, proc in zip(paths, procs):
        pid, sig = proc.pid, abs(proc.returncode)
        displayed=False
        if sig not in [None]:
            displayed=True
            log('[DEBUG] pid: {}, sig: {}'.format(pid, sig))
        if sig not in [None, 0, signal.SIGTERM]:
            if not displayed:
               log('[DEBUG] pid: {}, sig: {}'.format(pid, sig))

            # Attempt to get register values
            regs,coredump = get_core_dump_regs(path, pid, log)
            #log('[DEBUG]------\n[DEBUG] Coredump:\n{}\n[DEBUG]------'.format(coredump))
            if regs is not None or sig>=64: # or sig == 9:
                # If a core dump was generated, report this as a crash
                # log('Process generated signal (pid: {}, signal: {}) - {}\n'.format(pid, sig, testpath))
                log('Process generated signal (pid: {}, signal: {})'.format(pid, sig))

                if regs is not None:
                    # Report the register states
                    reg_str = ' '.join(['{}:{}'.format(reg, val) for reg, val in regs.items()])
                    log('register states - {}'.format(reg_str))

    # Final cleanup
    #log('cleanup')
    clean_cores(paths, procs)


def get_core_dump_regs(path, pid, log):
    """ Read all register values from a core dump
    MacOS:   all core dumps are stored as /cores/core.[pid]
    Linux:   the core dump is stored as a 'core' file in the cwd
    Windows: If the given registry file was used, core dumps are stored in %LOCALAPPDATA%\CrashDumps

    Args:
        path (str): path to the executable that generated the dump
        pid (int): pid of the process that generated the core dump
        log ((str) -> None): logging function used to report information
    Returns:
        (dict): Registers and their values
    """
    # Create a gdb/lldb/cdb command to get regs
    if IS_DARWIN:
        cmd = [
            'lldb',
            '--core', '/cores/core.{}'.format(pid),
            '--batch', '--one-line', 'register read'
        ]
    elif IS_LINUX:
        cmd = [
            'gdb',
            '--core', 'core',
            '--batch', 
            '-ex', 'info registers', 
            '-ex','backtrace'
            #,
            #'-ex','x/16wx $esp-8',
            #'-ex','x/a  (void*)($esp+0x14)'
        ]
    elif IS_WINDOWS:
        # Dumps are named "[filename.exe].[pid].dmp"
        dmp_name = '{}.{}.dmp'.format(os.path.basename(path), pid)
        cmd = [
            CDB_PATH,
            '-z', os.path.join(DUMP_DIR, dmp_name),
            '-c', 'q'  # Registers already get printed when the dump is loaded
                       # quit immediately
        ]

    # Read the registers
    #log('cmd={}'.format(' '.join(cmd)))
    dbg_out = b'\n'.join(sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE).communicate())
    #log('dbg_out={}'.format(dbg_out))

    # Batch commands return successful even if there was an error loading a file
    # Check for these strings in the output instead
    errs = [
        b'No such file or directory',
        b"doesn't exist",
        b'cannot find the file specified'
    ]

    if any(err in dbg_out for err in errs):
        log('Core dump not found, are they enabled on your system?')
        return None,None

    # Parse out registers/values
    regs = {}
    if IS_WINDOWS:
        for match in re.finditer(r'([a-z]+)=([a-fA-F0-9]+)', dbg_out):
            regs[match.group(1)] = match.group(2)
    else:
        for line in dbg_out.split(b'\n'):
            # Try to match a register value
            #match = re.search(r'([a-z]+)[=\ ]+0x([a-fA-F0-9]+)', line)
            #match = re.search(r'([a-z]+)[=\ ]+0x([a-fA-F0-9]+)', codecs.decode(line,'utf-8'))
            match = re.search(r'([a-z]+)[=\ ]+0x([a-fA-F0-9]+)', codecs.decode(line,'ISO-8859-1'))
            if match is not None:
                regs[match.group(1)] = match.group(2)

    return regs,dbg_out


def clean_cores(paths, procs):
    """ Delete all generated core dumps

    Args:
        paths (list): paths to all challenges that were launched
        procs (list): List of all processes that may have generated core dumps
    """
    if IS_DARWIN:
        list(map(try_delete, ['/cores/core.{}'.format(p.pid) for p in procs]))
    elif IS_LINUX:
        try_delete('core')
    elif IS_WINDOWS:
        for path, proc in zip(paths, procs):
            dmp_name = '{}.{}.dmp'.format(os.path.basename(path), proc.pid)
            try_delete(os.path.join(DUMP_DIR, dmp_name))
