#!/usr/bin/env python3

"""
CB POV / Poll communication verification tool

Copyright (C) 2014 - Brian Caswell <bmc@lungetech.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

This tool allows for deterministic communication to a CGC Challenge Binary
using a Challenge Binary as input.

1 - http://testanything.org/
"""

import subprocess as sp
import multiprocessing as mp
import random
import argparse
import os
import signal
import struct
import threading
import codecs

from common import IS_WINDOWS, Timeout, TimeoutError
import challenge_runner


def get_fd(fileobj):
    """ Gets the file descriptor for a given fileobject

    On Unix systems this returns the result of fileno()

    On Windows systems, fileno() returns a HANDLE. This will open
    that HANDLE and return a CRT file descriptor
    """
    if IS_WINDOWS:
        import msvcrt
        return msvcrt.open_osfhandle(fileobj.fileno(), os.O_TEXT)
    return fileobj.fileno()


class TestFailure(Exception):
    """ Exception to be used by Throw(), to allow catching of test failures """
    pass


class Throw(object):
    """Throw - Perform the interactions with a CB

    This class implements the basic methods to interact with a CB, verifying
    the interaction works as expected.

    Usage:
        a = Throw((source_ip, source_port), (target_ip, target_port), POV,
                  timeout, should_debug)
        a.run()

    Attributes:
        cb_paths: List of paths to all cb executables

        count: Number of actions performed

        debug: Is debugging enabled

        failed: Number of actions that did not work as expected

        passed: Number of actions that did worked as expected

        pov: POV, as defined by POV()

        timeout: connection timeout
    """
    def __init__(self, cb_paths, pov, timeout, debug, pov_seed, dbi=None):
        self.cb_paths = cb_paths
        self.pov = pov
        self.debug = debug
        self.timeout = timeout
        self.pov_seed = pov_seed
        self.dbi = dbi
        self.returncode = None

    def log(self, data):
        print("# %s" % data)

    def count_bits_set(self, value):
        count = 0
        while value:
            value &= value - 1
            count += 1
        return count

    def read_all(self, fd, data_len):
        data = b''
        if self.debug:
            self.log('read_all')
        while len(data) < data_len:
            read = os.read(fd, data_len - len(data))
            assert len(read)
            data += read
            if self.debug:
                self.log('read: {}'.format(read))
        if self.debug:
            self.log('data: {}'.format(data))
        return data

    def pov_negotiate(self, pipefd):
        MIN_BITS = 0

        if self.debug:
            self.log("negotiating")

        data = self.read_all(pipefd, 4)
        pov_type = struct.unpack('<L', data)[0]
        assert pov_type in [1, 2], 'invalid pov type'

        self.log("negotiation type: %d" % pov_type)

        if pov_type == 1:
            data = self.read_all(pipefd, 12)
            ipmask, regmask, regnum = struct.unpack('<LLL', data)
            accept = True

            if self.count_bits_set(ipmask) < MIN_BITS:
                self.log('not enough bits in IP mask')
                accept = False

            if self.count_bits_set(regmask) < MIN_BITS:
                self.log('not enough bits in REG mask')
                accept = False

            if regnum > 7:
                self.log('invalid GPR')
                accept = False

            if accept:
                ip = random.randint(0, 0xFFFFFFFF) & ipmask
                reg = random.randint(0, 0xFFFFFFFF) & regmask

                self.log('type 1 masks: %08x %08x' % (ipmask, regmask))
                self.log('type 1 pov: %08x %08x %d' % (ip, reg, regnum))

                pov_values = struct.pack('<LL', ip, reg)
                os.write(pipefd, pov_values)

        if pov_type == 2:
            PAGE_ADDR = 0x4347C000
            PAGE_LENGTH = 0x1000
            PAGE_BYTES = 4

            self.log("sending page location: %d, %d, %d" % (PAGE_ADDR, PAGE_LENGTH, PAGE_BYTES))
            pov_location = struct.pack('<LLL', PAGE_ADDR, PAGE_LENGTH, PAGE_BYTES)
            os.write(pipefd, pov_location)

            if self.debug:
                self.log("getting secret")
            data = self.read_all(pipefd, 4)
            #self.log("secret value: %s" % data.encode('hex'))
            self.log("secret value: %s" % codecs.encode(data,'hex'))

        if self.debug:
            self.log('done')

    def _launch_pov_unix(self, mainproc, pipe):
        # NOTE: This is running a forked process, free to clobber fds
        # This is mostly unchanged from the original source
        if self.timeout > 0:
            signal.alarm(self.timeout)

        # Setup fds for communication
        # executable under test's stdout goes to STDIN
        os.dup2(mainproc.stdout.fileno(), 0)
        # executable under test's stdin goes to STDOUT
        os.dup2(mainproc.stdin.fileno(), 1)
        os.dup2(pipe.fileno(), 3)

        if not self.debug:
            null = os.open('/dev/null', 0)
            os.dup2(null, 2)
            os.close(null)

        args = [self.pov]
        if self.pov_seed:
            args.append('seed=%s' % self.pov_seed)

        # Launch the POV
        os.execv(self.pov, args)
        #stdout2file.close()
        #exe2file.close()
        exit(-1)

    def _launch_pov_win(self, mainproc, pipe):
        import _subprocess as _sp

        cmd = [self.pov]
        if self.pov_seed:
            cmd.append('seed=%s' % self.pov_seed)

        # The pipe HANDLE isn't inheritable, make a duplicate that is
        cur_proc = _sp.GetCurrentProcess()
        inh_pipe = _sp.DuplicateHandle(cur_proc,       # Source process
                                       pipe.fileno(),  # HANDLE
                                       cur_proc,       # Target process
                                       0,              # Desired access
                                       1,              # Inheritable
                                       _sp.DUPLICATE_SAME_ACCESS)  # Options

        # Run the POV
        pov_proc = sp.Popen(cmd,
                            # Passing the HANDLE value here through an environment variable
                            # libpov will grab this and open it in fd 3
                            # see: include/libpov/pov.c - DLLMain
                            env={'POV_FD': str(int(inh_pipe))},

                            # stdin/out connect to the cb directly
                            stdin=mainproc.stdout,
                            stdout=mainproc.stdin)
        pov_proc.wait()

    def launch_pov(self, mainproc, pipe):
        if IS_WINDOWS:
            # Can't pass process/pipe handles to another process here, using a thread
            pov_runner = threading.Thread(target=self._launch_pov_win, args=(mainproc, pipe))
            pov_runner.setDaemon(True)
        else:
            # Fork on unix systems so we can dup fds where we want them
            pov_runner = mp.Process(target=self._launch_pov_unix, args=(mainproc, pipe))

        pov_runner.start()
        return pov_runner

    def gen_seed(self):
        """ Prepare the seed that will be used in the replay """
        seed = os.urandom(48)
        #self.log("using seed: %s" % seed.encode('hex'))
        self.log("using seed: %s" % codecs.encode(seed, 'hex').decode('ascii'))
        #return seed.encode('hex')
        return codecs.encode(seed,'hex')

    def run(self):
        """ Iteratively execute each of the actions within the POV

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: if a POV action is not in the pre-defined methods
        """
        self.log('%s' % (self.pov))

        # Get the seed for the tests
        seed = self.gen_seed()

        # Launch the challenges
        challenges=self.cb_paths
        if self.dbi:
           for i,x in enumerate(challenges):
                challenges[i]=self.dbi+" "+os.path.abspath(x)
        self.procs, watcher = challenge_runner.run(challenges, self.timeout, seed, self.log)

        # Setup and run the POV
        pov_pipes = mp.Pipe(duplex=True)

        #chal_pipes = mp.Pipe(duplex=True)
        # Start a thread to buffer data from the challenges' stdout
        #outbuf_thread = threading.Thread(target=self.buffer_pipe_data, args=(chal_pipes[0],pov_pipes[1],"replay.pov.out.log",))
        #outbuf_thread.setDaemon(True)
        #outbuf_thread.start()
        #inbuf_thread = threading.Thread(target=self.buffer_pipe_data, args=(pov_pipes[1],chal_pipes[0],"replay.pov.log",))
        #inbuf_thread.setDaemon(True)
        #inbuf_thread.start()
        
        #pov_runner = self.launch_pov(self.procs[0], chal_pipes[1])
        pov_runner = self.launch_pov(self.procs[0], pov_pipes[1])

        pov_negotiate_fail=False
        if self.timeout > 0:
            neg_thread = threading.Thread(target=self.pov_negotiate, args=(get_fd(pov_pipes[0]),))
            neg_thread.daemon=True
            neg_thread.start()
            neg_thread.join(self.timeout)
       
            if neg_thread.is_alive():
                self.log('pov negotiation timed out')
                pov_negotiate_fail=True
            
        #if self.timeout > 0:
        #    try:
        #        with Timeout(self.timeout + 1):
        #            self.pov_negotiate(get_fd(pov_pipes[0]))
        #    except TimeoutError:
        #        self.log('pov negotiation timed out')
        #        pass
        #else:
        #    self.log("No negotiation needed?")
        #    self.pov_negotiate()

        if self.debug:
            self.log('waiting')

        # Wait for the POV to finish and results to get logged
        pov_runner.join()
        watcher.join()

        self.log('END REPLAY')

        proc = self.procs[0]
        retval = proc.poll()
        self.returncode=self.procs[0].returncode
        #self.log("pov_runner.exitcode = {}".format(pov_runner.exitcode))
        #self.log("watcher.is_alive() = {}".format(watcher.is_alive()))

        if retval is None:
            try:
                proc.wait(timeout=1)
            except TimeoutExpired:
                self.log('terminating proc')
                proc.terminate()
        else:
            self.returncode=retval

        # Wait for the watcher to report its results
        #return self.procs[0].returncode
        ret=( self.returncode, pov_runner.exitcode, pov_negotiate_fail)
        self.log("binary return code, pov exit code, pov negotiation fail= "+str(ret))
        return ret

    def buffer_pipe_data(self, pipe_in, pipe_out,logfile):
        """ Continuously reads and buffers data from a pipe

        This will block when attempting to read data and should be run
        in a separate thread

        Args:
            pipe: readable fileobject for a pipe
        """
        o=open(logfile,"wb")
        while True:
            c = pipe_in.recv_bytes(1)
            if c in [None, b'']:
                break
            o.write(c)
            pipe_out.send_bytes(c)




def run_pov(cbs, pov, timeout, debug, pov_seed, dbi):
    """
    Parse and Throw a POV/Poll

    Arguments:
        cbs: List of paths to all cb executables
        pov: filename of the POV
        timeout: How long the POV communication is allowed to take
        debug: Flag to enable debug logs
        negotate: Should PRNG be negotiated with the CB
        pov_seed: the POV seed to use

    Returns:
        The number of passed tests
        The number of failed tests
        A list containing the logs

    Raises:
        Exception if parsing the POV times out
    """

    thrower = Throw(cbs, pov, timeout, debug, pov_seed, dbi)
    return thrower.run()


def main():
    """ Parse and Throw the POVs """
    parser = argparse.ArgumentParser(description='Send CB based CGC Polls and POVs')
    required = parser.add_argument_group(title='required arguments')
    required.add_argument('--cbs', nargs='+', required=True,
                          help='List of challenge binaries to run on the server')
    required.add_argument('files', metavar='pov', type=str, nargs='+',
                          help='pov file')
    parser.add_argument('--timeout', required=False, type=int, default=15,
                        help='Connect timeout')
    parser.add_argument('--debug', required=False, action='store_true',
                        default=False, help='Enable debugging output')
    parser.add_argument('--negotiate', required=False, action='store_true',
                        default=False, help='The CB seed should be negotiated')
    parser.add_argument('--pov_seed', required=False, type=str,
                        help='Specify the POV Seed')

    parser.add_argument('--sigok', required=False, action="append", type=int,
                        help='Specify signal values that are okay to terminate with')

    parser.add_argument('--dbi', required=False, type=str, default=None, 
    help='Specify any dynamic binary instrumentation (like valgrind) to be prepended to executable under test\
	e.g. --dbi "/usr/bin/valgrind --tool=callgrind --log-file=tramp.cg.log --callgrind-out-file=tramp.cg.out"')



    args = parser.parse_args()
	# SIGILL is 4, SIGTERM is 11, signals 32,33 don't exist
    #fatals=[4,11,32,33,124,125,126,127]; 
    fatals=[4,11,33,124,125,126,127]; 
    for i in range(len(fatals)):
       if fatals[i] <= 255:
           fatals.append(fatals[i]+128)
    sig_okay = [i for i in range(256) if i not in fatals]
    if args.sigok:
        sig_okay.extend(args.sigok)

    assert len(args.files)
    for filename in args.files:
        assert os.path.isfile(filename), "pov must be a file: %s" % repr(filename)

    status=list()
    seed = None
    if args.dbi:
        args.timeout=5*args.timeout
    if args.pov_seed:
        seed=codecs.encode(seed,'hex')
    for pov in args.files:
        stat,pov_stat,negot_failed = run_pov(args.cbs, pov, args.timeout,
                         args.debug, seed,args.dbi)
        exe_status= abs(stat) not in sig_okay
        pov_status= abs(pov_stat) not in sig_okay
        status.append(exe_status or pov_status or negot_failed)
    
    return any(status)


if __name__ == "__main__":
    exit(main())
