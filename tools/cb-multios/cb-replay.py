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
using a communication spec [0] defined in XML.  Results are logged in the TAP
format [1].

0 - file:///usr/share/cgc-docs/replay.dtd
1 - http://testanything.org/
"""

import os
import argparse
import multiprocessing as mp
import re
import socket
import time
import threading
import zipfile
import defusedxml.ElementTree as ET
import codecs

from common import Timeout, TimeoutError
from subprocess import TimeoutExpired
import challenge_runner

gen_rep_log=[False,'seed.log','replay.log','replay.out.log']

test={'enabled':False,'id':None,'expected':bytearray(),'write':bytearray(),'seed':None}

def enable_json_dump():
    test['enabled']=True

#def json_append_expected_data(bdata):
#    if test['enabled']:
#        for i in bdata:
#            try:
#                test['expected'].extend(i)
#            except Exception as e:
#                print(f"type = {type(i)}",flush=True)
#                print(e)
#                raise(e)

def json_append_write_data(bdata):
    if test['enabled']:
        for i in bdata:
            try:
                if type(i)==bytes:
                    test['write'].extend(i)
                if type(i)==str:
                    test['write'].extend(bytes(i,encoding="raw_unicode_escape"))
            except Exception as e:
                print(f"type = {type(i)}",flush=True)
                print(e)
                raise(e)

def json_seed(seed):
    if test['enabled']:
        test['seed']=seed

def json_id(idn):
    if test['enabled']:
        test['id']=idn

def write_json():
    if test['enabled']:
        dest=f"{test['id']}.pkl"
        if os.path.exists(dest):
            os.remove(dest)
        p=os.path.dirname(dest)
        if p!="" and not os.path.exists(p):
            os.makedirs(p)
        with open(dest,'wb') as f:
            import pickle
            pickle.dump(test,f)
            f.close()

class RegexMatch(object):
    """ Simple wrapper for handling regexes in Throw.

    Attributes:
        group: which re group to use when extracting data
        regex: The compiled re to be evaluated

    """
    def __init__(self, regex, group=None):
        if group is None:
            group = 0

        self.regex = regex
        self.group = group

    def match(self, data):
        """
        Match the compiled regular expression

        Arguments:
            data: Data to match

        Returns:
            Result of the re.match call

        Raises
            None
        """

        return self.regex.match(data)


class _ValueStr(str):
    """ Wrapper class, used to specify the string is meant to be a 'key' in the
    Throw.values key/value store."""
    pass


class TestFailure(Exception):
    """ Exception to be used by Throw(), to allow catching of test failures """
    pass


class Throw(object):
    """Throw - Perform the interactions with a CB

    This class implements the basic methods to interact with a CB, verifying
    the interaction works as expected.

    Usage:
        a = Throw((source_ip, source_port), (target_ip, target_port), POV,
                  timeout, should_debug, negotiate)
        a.run()

    Attributes:
        cb_paths: List of paths to all cb executables

        count: Number of actions performed

        debug: Is debugging enabled

        failed: Number of actions that did not work as expected

        passed: Number of actions that did worked as expected

        pov: POV, as defined by POV()

        sock: TCP Socket to the CB

        timeout: connection timeout

        values: Variable dictionary

        logs: all of the output from the interactions

        negotiate: Should the CB negotiation process happen
    """
    def __init__(self, cb_paths, pov, timeout, debug, negotiate, dbi=None, perf=False):
        self.cb_paths = cb_paths
        self.count = 0
        self.failed = 0
        self.passed = 0
        self.pov = pov
        self.debug = debug
        self.timeout = timeout
        self.values = {}
        self.logs = []
        self._read_buffer = ''
        self.negotiate = negotiate
        self.dbi = dbi
        self.perf = perf

        self.procs = None
        self.pipe_raw = []
        self.pipe_buf = ''

    def is_ok(self, expected, result, message):
        """ Verifies 'expected' is equal to 'result', logging results in TAP
             format

        Args:
            expected: Expected value
            result:   Action value
            message:  String describing the action being evaluated

        Returns:
            legnth: If the 'expected' result is a string, returns the length of
                the string, otherwise 0

        Raises:
            None
        """

        if isinstance(expected, _ValueStr):
            message += ' (expanded from %s)' % repr(expected)
            if expected not in self.values:
                message += ' value not provided'
                self.log_fail(message)
                return 0
            expected = self.values[expected]

        if isinstance(expected, str):
            if result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        elif isinstance(expected, bytes):
            if result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        else:
            if result == expected:
                self.log_ok(message)
                return 0

        if self.debug:
            self.log('expected: %s' % repr(expected))
            self.log('result: %s' % repr(result))

        self.log_fail(message)
        return 0

    def is_not(self, expected, result, message):
        """ Verifies 'expected' is not equal to 'result', logging results in
            TAP format

        Args:
            expected: Expected value
            result:   Action value
            message:  String describing the action being evaluated

        Returns:
            legnth: If the 'expected' result is a string, returns the length of
                the string, otherwise 0

        Raises:
            None
        """
        if isinstance(expected, _ValueStr):
            message += ' (expanded from %s)' % repr(expected)
            if expected not in self.values:
                message += ' value not provided'
                self.log_fail(message)
                return 0
            expected = self.values[expected]

        if isinstance(expected, str):
            if not result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        elif isinstance(expected, bytes):
            if result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        else:
            if result != expected:
                self.log_ok(message)
                return 0

        if self.debug:
            self.log('these are expected to be different:')
            self.log('expected: %s' % repr(expected))
            self.log('result: %s' % repr(result))
        self.log_fail(message)
        return 0

    def log_ok(self, message):
        """ Log a test that passed in the TAP format

        Args:
            message:  String describing the action that 'passed'

        Returns:
            None

        Raises:
            None
        """
        self.passed += 1
        self.count += 1
        self.logs.append("ok %d - %s" % (self.count, message))

    def log_fail(self, message):
        """ Log a test that failed in the TAP format

        Args:
            message:  String describing the action that 'passed'

        Returns:
            None

        Raises:
            None
        """
        self.failed += 1
        self.count += 1
        self.logs.append("not ok %d - %s" % (self.count, message))
        raise TestFailure('failed: %s' % message)

    def log(self, message):
        """ Log diagnostic information in the TAP format

        Args:
            message:  String being logged

        Returns:
            None

        Raises:
            None
        """
        self.logs.append("# %s" % message)

    def sleep(self, value):
        """ Sleep a specified amount

        Args:
            value:  Amount of time to sleep, specified in miliseconds

        Returns:
            None

        Raises:
            None
        """
        time.sleep(value)
        self.log_ok("slept %f" % value)

    def declare(self, values):
        """ Declare variables for use within the current CB communication
            iteration

        Args:
            values:  Dictionary of key/value pair values to be set

        Returns:
            None

        Raises:
            None
        """
        self.values.update(values)

        set_values = [repr(x) for x in list(values.keys())]
        self.log_ok("set values: %s" % ', '.join(set_values))

    def _perform_match(self, match, data, invert=False):
        """ Validate the data read from the CB is as expected

        Args:
            match:  Pre-parsed expression to validate the data from the CB
            data:  Data read from the CB

        Returns:
            None

        Raises:
            None
        """
        offset = 0
        for item in match:
            if isinstance(item, str):
                if invert:
                    offset += self.is_not(item, data[offset:],
                                          'match: not string')
                else:
                    offset += self.is_ok(item, data[offset:], 'match: string')
            elif isinstance(item,bytes):
                if invert:
                    offset += self.is_not(item, data[offset:].encode('ISO-8859-1'),
                                          'match: not string')
                else:
                    offset += self.is_ok(item, data[offset:].encode('ISO-8859-1'), 
                                         'match: string')
            elif hasattr(item, 'match'):
                match = item.match(data[offset:])
                if match:
                    if invert:
                        if self.debug:
                            self.log('pattern: %s' % repr(item.regex.pattern))
                            self.log('data: %s' % repr(data[offset:]))
                        self.log_fail('match: not pcre')
                    else:
                        self.log_ok('match: pcre')
                    offset += match.end()
                else:
                    if invert:
                        self.log_ok('match: not pcre')
                    else:
                        if self.debug:
                            self.log('pattern: %s' % repr(item.regex.pattern))
                            self.log('data: %s' % repr(data[offset:]))
                        self.log_fail('match: pcre')
            else:
                raise Exception('unknown match type: %s' % repr(item))

    def _perform_expr(self, expr, key, data):
        """ Extract a value from the value read from the CB using 'slice' or
        'pcre'

        Args:
            expr:  Pre-parsed expression to extract the value
            key:   Key to store the value in the instance iteration
            data:  Data read from the CB

        Returns:
            None

        Raises:
            None
        """
        value = None

        # self.log('PERFORMING EXPR (%s): %s' % (key, repr(expr)))
        # self.log('DATA: %s' % repr(data))
        if isinstance(expr, slice):
            value = data[expr]
        elif isinstance(expr, RegexMatch):
            match = expr.match(data)
            if match:
                try:
                    value = match.group(expr.group)
                except IndexError:
                    self.log_fail('match group unavailable')
            else:
                self.log_fail('match failed')

        else:
            self.log_fail('unknown expr type: %s' % repr(expr))

        if value is not None:
            self.values[key] = value
            if self.debug:
                self.log('set %s to %s' % (key, value.encode('hex')))
            self.log_ok('set %s' % (key))

    def _read_len(self, read_len):
        """
        Read a specified size, but only ever get 4096 bytes from the socket
        """
        if len(self._read_buffer) >= read_len:
            data = self._read_buffer[:read_len]
            self._read_buffer = self._read_buffer[read_len:]
            return data

        data = [self._read_buffer]
        data_len = len(self._read_buffer)
        while data_len < read_len:
            left = read_len - data_len
            if self.debug:
                self.log("#bytes left >>{}<<".format(left)) 
            data_read = self.read_from_proc(max(4096, left))
            if self.debug:
                self.log("read_len: >>{}<<".format(data_read)) 
            if len(data_read) == 0:
                # data_read = '\n'
                self.log_fail('recv failed. (%s so far)' % repr(data))
                self._read_buffer = b''.join(data)
                return ''

            data.append(data_read)
            data_len += len(data_read)
        if self.debug:
            self.log("read: >>{}<<".format(data))
        data = ''.join(data)
        self._read_buffer = data[read_len:]
        return data[:read_len]

    def _read_delim(self, delim):
        """
        Read until a delimiter is found, but only ever get 4096 bytes from the
        socket
        """
        delim=delim.decode('ISO-8859-1')
        while delim not in self._read_buffer:
            data_read = self.read_from_proc(4096)
            #print("# _read_delim : data_read = {} [delim={}]".format(data_read,delim))
            if len(data_read) == 0:
                self.log_fail('recv failed.  No data returned.')
                return ''
            self._read_buffer += data_read

        depth = self._read_buffer.index(delim) + len(delim)
        data = self._read_buffer[:depth]
        self._read_buffer = self._read_buffer[depth:]
        return data

    def read(self, read_args):
        """ Read data from the CB, validating the results

        Args:
            read_args:  Dictionary of arguments

        Returns:
            None

        Raises:
            Exception: if 'expr' argument is provided and 'assign' is not
        """
        data = ''
        try:
            if 'length' in read_args:
                #print("length = {}".format(read_args['length']))
                data = self._read_len(read_args['length'])
                self.is_ok(read_args['length'], len(data), 'read length')
            elif 'delim' in read_args:
                data = self._read_delim(read_args['delim'])
            if self.debug:
                self.log('received %s' % data)
        except socket.error as err:
            self.log_fail('recv failed: %s' % str(err))

        if 'echo' in read_args and self.debug:
            assert read_args['echo'] in ['yes', 'no', 'ascii']

            if 'yes' == read_args['echo']:
                self.log('received %s' % data.encode('hex'))
            elif 'ascii' == read_args['echo']:
                self.log('received %s' % repr(data))

        if 'match' in read_args:
            self._perform_match(read_args['match']['values'], data,
                                read_args['match']['invert'])

        if 'expr' in read_args:
            assert 'assign' in read_args
            self._perform_expr(read_args['expr'], read_args['assign'], data)

    def write(self, args):
        """ Write data to the CB

        Args:
            args:  Dictionary of arguments

        Returns:
            None

        Raises:
            None
        """
        data = []
        for value in args['value']:
            v = value
            if isinstance(value, _ValueStr):
                if value not in self.values:
                    self.log_fail('write failed: %s not available' % value)
                    return
                v = self.values[value]
            if isinstance(v,str):
                v = v.encode('ISO-8859-1')
            data.append(v)
        to_send = b''.join(data)
        #self.log('sending "%s"' % to_send )

        if self.debug:
            if args['echo'] == 'yes':
                self.log('writing: %s' % to_send.encode('hex'))
            elif args['echo'] == 'ascii':
                self.log('writing: %s' % repr(to_send))

        try:
            sent = self.write_to_proc(to_send)
            if sent != len(to_send):
                self.log_fail('write failed.  wrote %d of %d bytes' %
                              (sent, len(to_send)))
                return
            else:
                self.log_ok('write: sent %d bytes' % sent)
        except socket.error:
            self.log_fail('write failed')

    def write_to_proc(self, data):
        """ Writes data to the stdin pipe of the challenges

        Args:
            data (str): data to be written

        Returns:
            (int): amount of data written, or 0 on error
        """
        try:
            #self.procs[0].stdin.write(data.encode())
            #x=data.encode('utf-8')
            #x=data.encode('ISO-8859-1')
            x=data
            #print("type(self.procs[0])={} [x={}]".format(type(self.procs[0]),x),flush=True)
            self.procs[0].stdin.write(x)
            self.procs[0].stdin.flush()
            return len(data)
        except IOError:
            return 0

    def read_from_proc(self, size):
        """ Reads a chosen amount of data from the stdout pipe of the challenges

        Args:
            size (int): amount of data to read

        Returns:
            (str): data read from the pipe
        """
        # Wait until there's data in the raw buffer
        while len(self.pipe_raw) == 0:
            time.sleep(0.01)

        # Fill up the temp buffer until we have the requested amount of data
        while len(self.pipe_buf) < size and len(self.pipe_raw) != 0:
            #self.pipe_buf += self.pipe_raw.pop(0).decode('ascii')
            self.pipe_buf += self.pipe_raw.pop(0).decode('ISO-8859-1')

            # Convert CRLF to LF to match what the POLLs expect
            if self.pipe_buf.endswith('\r\n'):
                self.pipe_buf = self.pipe_buf[:-2] + '\n'

        #print("read_from_proc: >>{}<<".format(self.pipe_buf),end='')
        # Return the amount requested
        res = self.pipe_buf[:size]
        self.pipe_buf = self.pipe_buf[size:]
        return res

    def buffer_pipe_data(self, pipe):
        """ Continuously reads and buffers data from a pipe

        This will block when attempting to read data and should be run
        in a separate thread

        Args:
            pipe: readable fileobject for a pipe
        """
        while True:
            c = pipe.read(1)
            if c in [None, b'']:
                break
            self.pipe_raw.append(c)

    def gen_seed(self):
        """ Prepare the seed that will be used in the replay """
        seed = self.pov.seed

        if seed is None:
            print("# No seed specified, using random seed")
            seed = int.from_bytes(os.urandom(48),byteorder='little')
            self.log("random seed: %s" % hex(seed))

        #self.log("using seed: %s" % seed.encode('hex'))
        #return seed.encode('hex')
        seed_val=hex(seed)[2:].zfill(96)
        self.log("using seed: %s" % seed_val)
        json_seed(seed_val)
        return seed_val

    def kill_procs(self):
        proc = self.procs[0]
        proc.wait(timeout=1)
        proc.kill()
        
    def run(self):
        """ Iteratively execute each of the actions within the POV

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: if a POV action is not in the pre-defined methods
        """

        self.log('%s - %s' % (self.pov.name, self.pov.filename))

        methods = {
            'sleep': self.sleep,
            'declare': self.declare,
            'read': self.read,
            'write': self.write,
        }

        # Get the seed for the tests
        seed = self.gen_seed()

        # Launch all challenges
        challenges=self.cb_paths
        if self.dbi:
           for i,x in enumerate(challenges):
                challenges[i]=self.dbi+" "+os.path.abspath(x)
           self.log('DBI challenge: '+challenges[0])
        elif self.perf:
           for i,x in enumerate(challenges):
                # please note that the performance output is sent to STDERR, not STDOUT
                challenges[i]="/usr/bin/perf stat "+os.path.abspath(x)
           self.log('Obtaining run-time for: '+challenges[0])

        #PEMMA
        if gen_rep_log:
            o=open(gen_rep_log[1],"wb")
            o.write(bytes(seed,'utf-8'))
        self.procs, watcher = challenge_runner.run(challenges, self.timeout, seed, self.log,\
                               True )

        # Start a thread to buffer data from the challenges' stdout
        buf_thread = threading.Thread(target=self.buffer_pipe_data, args=(self.procs[0].stdout,))
        buf_thread.setDaemon(True)
        buf_thread.start()

        # Everything is ready, now we can run the test
        for method, arguments in self.pov:
            assert method in methods, "%s not in methods" % method
            try:
                #self.log("[method : {}][arguments : {}]".format(method,arguments))
                methods[method](arguments)
            except TestFailure:
                self.log('stopping due to failure')
                break

        # The current test is done, kill the main process if it's still running
        proc = self.procs[0]
        retval = proc.poll()
        if retval is None:
            try:
                proc.wait(timeout=1)
            except TimeoutExpired:
                self.log('terminating proc')
                proc.terminate()

        # Wait for the watcher to report its results
        buf_thread.join()
        watcher.join()
        if buf_thread.is_alive():
            self.log('buf_thread is alive')
        else:
            self.log('buf_thread is dead')
        if watcher.is_alive():
            self.log('watcher is alive')
        else:
            self.log('watcher is dead')


    def dump(self):
        """ Log information for the current POV iteraction

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        if len(self.values) and self.debug:
            self.log("variables at end of interaction: ")
            for key in self.values:
                self.log("%s : %s" % (repr(key), repr(self.values[key])))
        self.log('tests passed: %d' % self.passed)
        self.log('tests failed: %d' % self.failed)


class POV(object):
    """POV - Parse a POV xml file

    This class implements a parser for the CGC POV/Poll format defined in
    replay.dtd.

    Usage:
        p = POV()
        p.parse(filename)
        p.dump()

    Attributes:
        name:  Name of the CB

        filename:  Filename of the CB definition

        _steps:  List of iteractions of a CB

        _variables:  List of variables used during CB interaction
    """
    def __init__(self, seed=None):
        self.filename = None
        self.name = None
        self._steps = []
        self._variables = []

        self.seed = seed

    def __iter__(self):
        """ Iterate over iteractions in a POV

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        for step in self._steps:
            yield step

    def mutate_seed(self):
        self.seed = ''.join(chr(ord(a) ^ 255) for a in self.seed)

    @staticmethod
    def compile_hex_match(data):
        """ Convert a string of hex values to their ascii value, skipping
        whitespace

        Args:
            data:  Hex string

        Returns:
            None

        Raises:
            None
        """
        for i in [' ', '\n', '\r', '\t']:
            data = data.replace(i, '')
        #return data.decode('hex')
        return bytes.fromhex(data).decode('ISO-8859-1')

    @staticmethod
    def compile_pcre(data):
        """ Compile a PCRE regular express for later use

        Args:
            data:  String to be compiled

        Returns:
            None

        Raises:
            None
        """
        pattern = re.compile(data, re.DOTALL)
        return RegexMatch(pattern)

    @staticmethod
    def compile_slice(data):
        """ Parse a slice XML element, into simplified Python slice format
        (<digits>:<digits>).

        Args:
            data:  XML element defining a slice

        Returns:
            None

        Raises:
            AssertionError: If the tag text is not empty
            AssertionError: If the tag name is not 'slice'
        """
        assert data.tag == 'slice'
        assert data.text is None
        begin = int(POV.get_attribute(data, 'begin', '0'))
        end = POV.get_attribute(data, 'end', None)
        if end is not None:
            end = int(end)
        return slice(begin, end)

    @staticmethod
    def compile_string_match(data):
        """ Parse a string into an 'asciic' format, for easy use.  Allows for
        \\r, \\n, \\t, \\\\, and hex values specified via C Style \\x notation.

        Args:
            data:  String to be parsed into a 'asciic' supported value.

        Returns:
            None

        Raises:
            AssertionError: if either of two characters following '\\x' are not
                hexidecimal values
            Exception: if the escaped value is not one of the supported escaped
                strings (See above)
        """

        # \\, \r, \n, \t \x(HEX)(HEX)
        data = str(data)  # no unicode support
        state = 0
        out = []
        chars = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\'}
        hex_chars = '0123456789abcdef'
        hex_tmp = ''
        for val in data:
            if state == 0:
                if val != '\\':
                    out.append(val.encode('ISO-8859-1'))
                    continue
                state = 1
            elif state == 1:
                if val in chars:
                    out.append(chars[val].encode('ISO-8859-1'))
                    state = 0
                    continue
                elif val == 'x':
                    state = 2
                else:
                    raise Exception('invalid asciic string (%s)' % repr(data))
            elif state == 2:
                assert val.lower() in hex_chars
                hex_tmp = val
                state = 3
            else:
                assert val.lower() in hex_chars
                hex_tmp += val
                #print(hex_tmp,end='')
                #out.append(hex_tmp.decode('hex'))
                #out.append(str(int(hex_tmp,16)))
                #out.append(bytes.fromhex(hex_tmp).decode('utf-8'))
                out.append(bytes.fromhex(hex_tmp))
                hex_tmp = ''
                state = 0
        x= b''.join(out)
        #print("in => {}; out => {}".format(data,x))
        return x

    @staticmethod
    def compile_string(data_type, data):
        """ Converts a string from a specified format into the converted into
        an optimized form for later use

        Args:
            data_type:  Which 'compiler' to use
            data:  String to be 'compiled'

        Returns:
            None

        Raises:
            None
        """
        funcs = {
            'pcre': POV.compile_pcre,
            'asciic': POV.compile_string_match,
            'hex': POV.compile_hex_match,
        }
        return funcs[data_type](data)

    @staticmethod
    def get_child(data, name):
        """ Retrieve the specified 'BeautifulSoup' child from the current
        element

        Args:
            data:  Current element that should be searched
            name:  Name of child element to be returned

        Returns:
            child: BeautifulSoup element

        Raises:
            AssertionError: if a child with the specified name is not contained
                in the specified element
        """
        child = data.findChild(name)
        assert child is not None
        return child

    @staticmethod
    def get_attribute(data, name, default=None, allowed=None):
        """ Return the named attribute from the current element.

        Args:
            data:  Element to read the named attribute
            name:  Name of attribute
            default:  Optional default value to be returne if the attribute is
                not provided
            allowed:  Optional list of allowed values

        Returns:
            None

        Raises:
            AssertionError: if the value is not in the specified allowed values
        """
        value = default
        if name in data.attrib:
            value = data.attrib[name]
        if allowed is not None:
            assert value in allowed
        return value

    def add_variable(self, name):
        """ Add a variable the POV interaction

        This allows for insurance of runtime access of initialized variables
        during parse time.

        Args:
            name:  Name of variable

        Returns:
            None

        Raises:
            None
        """
        if name not in self._variables:
            self._variables.append(name)

    def has_variable(self, name):
        """ Verify a variable has been defined

        Args:
            name:  Name of variable

        Returns:
            None

        Raises:
            None
        """
        return name in self._variables

    def add_step(self, step_type, data):
        """ Add a step to the POV iteraction sequence

        Args:
            step_type:  Type of interaction
            data:  Data for the interaction

        Returns:
            None

        Raises:
            AssertionError: if the step_type is not one of the pre-defined
                types
        """
        assert step_type in ['declare', 'sleep', 'read', 'write']
        self._steps.append((step_type, data))

    def parse_delay(self, data):
        """ Parse a 'delay' interaction XML element

        Args:
            data:  XML Element defining the 'delay' iteraction

        Returns:
            None

        Raises:
            AssertionError: if there is not only one child in the 'delay'
                element
        """
        self.add_step('sleep', float(data.text) / 1000)

    def parse_decl(self, data):
        """ Parse a 'decl' interaction XML element

        Args:
            data:  XML Element defining the 'decl' iteraction

        Returns:
            None

        Raises:
            AssertionError: If there is not two children in the 'decl' element
            AssertionError: If the 'var' child element is not defined
            AssertionError: If the 'var' child element does not have only one
                child
            AssertionError: If the 'value' child element is not defined
            AssertionError: If the 'value' child element does not have only one
                child
        """
        assert len(data) == 2
        assert data[0].tag == 'var'
        key = data[0].text

        values = []
        assert data[1].tag == 'value'
        assert len(data[1]) > 0
        for item in data[1]:
            values.append(self.parse_data(item))

        value = ''.join(values)

        self.add_variable(key)
        self.add_step('declare', {key: value})

    def parse_assign(self, data):
        """ Parse an 'assign' XML element

        Args:
            data:  XML Element defining the 'assign' iteraction

        Returns:
            None

        Raises:
            AssertionError: If the 'var' element is not defined
            AssertionError: If the 'var' element does not have only one child
            AssertionError: If the 'pcre' or 'slice' element of the 'assign'
                element is not defined
        """

        assert data.tag == 'assign'
        assert data[0].tag == 'var'
        assign = data[0].text
        self.add_variable(assign)

        if data[1].tag == 'pcre':
            expression = POV.compile_string('pcre', data[1].text)
            group = POV.get_attribute(data[1], 'group', '0')
            expression.group = int(group)

        elif data[1].tag == 'slice':
            expression = POV.compile_slice(data[1])
        else:
            raise Exception("unknown expr tag: %s" % data[1].tag)

        return assign, expression

    def parse_read(self, data):
        """ Parse a 'read' interaction XML element

        Args:
            data:  XML Element defining the 'read' iteraction

        Returns:
            None

        Raises:
            AssertionError: If the 'delim' element is defined, it does not have
                only one child
            AssertionError: If the 'length' element is defined, it does not
                have only one child
            AssertionError: If both 'delim' and 'length' are specified
            AssertionError: If neither 'delim' and 'length' are specified
            AssertionError: If the 'match' element is defined, it does not have
                only one child
            AssertionError: If the 'timeout' element is defined, it does not
                have only one child
        """
        # <!ELEMENT read ((length | delim),match?,assign?,timeout?)>
        # <!ATTLIST read echo (yes|no|ascii) "no">

        # defaults
        read_args = {'timeout': 0}

        # yay, pass by reference.  this allows us to just return when we're out
        # of sub-elements.
        self.add_step('read', read_args)

        read_args['echo'] = POV.get_attribute(data, 'echo', 'no', ['yes', 'no',
                                                                   'ascii'])

        assert len(data) > 0

        #children = data.getchildren()
        children = list(data)


        read_until = children.pop(0)

        if read_until.tag == 'length':
            read_args['length'] = int(read_until.text)
        elif read_until.tag == 'delim':
            read_args['delim'] = self.parse_data(read_until, 'asciic',
                                                 ['asciic', 'hex'])
        else:
            raise Exception('invalid first argument')

        if len(children) == 0:
            return
        current = children.pop(0)

        if current.tag == 'match':
            invert = False
            if POV.get_attribute(current, 'invert', 'false',
                                 ['false', 'true']) == 'true':
                invert = True

            assert len(current) > 0

            values = []
            for item in current:
                if item.tag == 'data':
                    values.append(self.parse_data(item, 'asciic',
                                                  ['asciic', 'hex']))
                elif item.tag == 'pcre':
                    values.append(POV.compile_string('pcre', item.text))
                elif item.tag == 'var':
                    values.append(_ValueStr(item.text))
                else:
                    raise Exception('invalid data.match element name: %s' %
                                    item.name)

            read_args['match'] = {'invert': invert, 'values': values}
            #json_append_expected_data(values)
            if gen_rep_log:
                try:
                    o=open(gen_rep_log[3],"ab")
                    bvalues=bytearray()
                    #print(f"values length = {len(values)} [type={type(values)}]")
                    #print(f"Values = '{values[0]}' (type = {type(values[0])}")
                    for v in values:
                        if isinstance(v,str): 
                            vvv=v.encode('ISO-8859-1')
                            o.write(vvv)
                        elif isinstance(v,bytes): 
                            o.write(v)
                    #try:
                    #    if (type(bvalues[0])==str):
                    #        o.write((b' '.join(bvalues)).decode('ISO-8859-1'))
                    #    else:
                    #        #o.write((b' '.join(values)).decode('ascii'))
                    #        o.write((b' '.join(bvalues)).decode('ISO-8859-1'))
                    #except:
                    o.close()
                except Exception as ex:
                    print("Exception while trying to write 'replay.out.log'")
                    #print(f"BValues = {[(b,type(b)) for b in bvalues]}")
                    #print(f"Values = {[(b,type(b)) for b in values]}")
                    print(ex)
                    pass

            if len(children) == 0:
                return
            current = children.pop(0)

        if current.tag == 'assign':
            assign, expr = self.parse_assign(current)
            read_args['assign'] = assign
            read_args['expr'] = expr
            if len(children) == 0:
                return
            current = children.pop(0)

        assert current.tag == 'timeout', "%s tag, not 'timeout'" % current.tag
        read_args['timeout'] = int(current.text)

    @staticmethod
    def parse_data(data, default=None, formats=None):
        """ Parse a 'data' element'

        Args:
            data: XML Element defining the 'data' item
            formats: Allowed formats

        Returns:
            A 'normalized' string

        Raises:
            AssertionError: If element is not named 'data'
            AssertionError: If the element has more than one child
        """

        if formats is None:
            formats = ['asciic', 'hex']

        if default is None:
            default = 'asciic'

        assert data.tag in ['data', 'delim', 'value']
        assert len(data.text) > 0
        data_format = POV.get_attribute(data, 'format', default, formats)
        return POV.compile_string(data_format, data.text)

    def parse_write(self, data):
        """ Parse a 'write' interaction XML element

        Args:
            data:  XML Element defining the 'write' iteraction

        Returns:
            None

        Raises:
            AssertionError: If any of the child elements do not have the name
                'data'
            AssertionError: If any of the 'data' elements have more than one
                child
        """
        # <!ELEMENT write (data+)>
        # <!ELEMENT data (#PCDATA)>
        # <!ATTLIST data format (asciic|hex) "asciic">

        # self._add_variables(name)

        values = []
        printmevalues = []
        assert len(data) > 0
        for val in data:
            if val.tag == 'data':
                values.append(self.parse_data(val))
                printmevalues.append(self.parse_data(val))
            else:
                assert val.tag == 'var'
                assert self.has_variable(val.text)
                values.append(_ValueStr(val.text))
                printmevalues.append("_ValueStr({})".format(val.text))

        echo = POV.get_attribute(data, 'echo', 'no', ['yes', 'no', 'ascii'])
        self.add_step('write', {'value': values, 'echo': echo})
        json_append_write_data(values)
        if gen_rep_log:
            try:
                o=open(gen_rep_log[2],"ab")
                i,v = (None,None)
                try:
                    for v in printmevalues:
                        if isinstance(v,str): 
                            vvv=v.encode('ISO-8859-1')
                            o.write(vvv)
                        elif isinstance(v,bytes): 
                            o.write(v)
                    #if (type(printmevalues[0])==str):
                    #if isinstance(printmevalues[0],bytes):
                    #    o.write(b' '.join(printmevalues))
                    #    #o.write((b' '.join(printmevalues)).decode('ISO-8859-1'))
                    #else:
                    #    o.write((' '.join(printmevalues)).encode('ISO-8859-1'))
                except Exception as e:
                    print("[values] Exception {}\nvalues = {},type(value[0])={}".format(e,printmevalues,type(printmevalues[0])))
                o.close()
            except Exception as ex:
                print("[replay.log] Exception while trying to write 'replay.log'")
                print(ex)
                pass

    def parse(self, raw_data, filename=None):
        """ Parse the specified replay XML

        Args:
            raw_data:  Raw XML to be parsed

        Returns:
            None

        Raises:
            AssertionError: If the XML file has more than top-level children
                (Expected: pov and doctype)
            AssertionError: If the first child is not a Doctype instance
            AssertionError: If the doctype does not specify the replay.dtd
            AssertionError: If the second child is not named 'pov'
            AssertionError: If the 'pov' element has more than two elements
            AssertionError: If the 'pov' element does not contain a 'cbid'
                element
            AssertionError: If the 'cbid' element value is blank
        """

        self.filename = filename

        tree = ET.fromstring(raw_data)
        assert tree.tag == 'pov'
        assert len(tree) in [2, 3]

        assert tree[0].tag == 'cbid'
        assert len(tree[0].tag) > 0
        self.name = tree[0].text

        assert tree[1].tag in ['seed', 'replay']

        seed_tree = None
        replay_tree = None
        if tree[1].tag == 'seed':
            seed_tree = tree[1]
            replay_tree = tree[2]
        else:
            seed_tree = None
            replay_tree = tree[1]

        if seed_tree is not None:
            assert len(seed_tree.tag) > 0
            seed = seed_tree.text
            assert len(seed) == 96
            if self.seed is not None:
                print("# Seed is set by XML and command line, using XML seed")
            #self.seed = seed.decode('hex')
            self.seed = int(seed,16)

        parse_fields = {
            'decl': self.parse_decl,
            'read': self.parse_read,
            'write': self.parse_write,
            'delay': self.parse_delay,
        }

        for replay_element in replay_tree:
            assert replay_element.tag in parse_fields
            #print("call : {}".format(parse_fields[replay_element.tag].__name__))
            parse_fields[replay_element.tag](replay_element)

    def dump(self):
        """ Print the steps in the POV, via repr

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        for step in self._steps:
            print(repr(step))


class Results(object):
    """ Class to handle gathering result stats from Throw() instances """
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = 0
        self.full_passed = 0

    def cb_pov_result(self, results):
        """
        Throw() result callback

        Arguments:
            results: tuple containing the number of results passed, failed, and
                a list of logs

        Returns:
            None

        Raises:
            None
        """
        got_passed, got_failed, got_logs, returncodes = results
        print('\n'.join(got_logs + ['END REPLAY']))
        self.passed += got_passed
        self.failed += got_failed
    # SIGILL is 4, SIGTERM is 11, signals 32,33 don't exist
        fatals=[4,11,33,124,125,126,127]; 
        for i in range(len(fatals)):
           if fatals[i] <= 255:
               fatals.append(fatals[i]+128)
        sig_okay = [i for i in range(256) if i not in fatals]
        failed=any([abs(stat) not in sig_okay for stat in returncodes])
        if got_failed > 0:
            self.errors += 1
        elif failed:
            self.errors += 1
        else:
            self.full_passed += 1


def run_pov(cbs, pov_info, timeout, debug, negotiate, cb_seed, munge_seed, dbi=None):
    """
    Parse and Throw a POV/Poll

    Arguments:
        cbs: List of paths to all cb executables
        pov_info: content/filename tuple of the POV
        timeout: How long the POV communication is allowed to take
        debug: Flag to enable debug logs
        negotiate: Should the poller negotiate with cb-server
        cb_seed: specify a seed to use in the pools
        munge_seed: should the seed be xored before use

    Returns:
        The number of passed tests
        The number of failed tests
        A list containing the logs

    Raises:
        Exception if parsing the POV times out
    """

    xml, filename = pov_info
    pov = POV(seed=cb_seed)
    error = None
    try:
        with Timeout(30):
            pov.parse(xml, filename=filename)
    except TimeoutError:
        error = "parsing %s timed out" % filename
    except ET.ParseError as err:
        error = "parsing %s errored: %s" % (filename, str(err))

    if munge_seed:
        pov.mutate_seed()

    cbs_timeout=timeout
    if dbi:
        cbs_timeout = 5*timeout
    thrower = Throw(cbs, pov, cbs_timeout, debug, negotiate, dbi)
    run_timeout=timeout
    if dbi:
        run_timeout = 50*timeout
    if error is not None:
        try:
            thrower.log_fail(error)
        except TestFailure:
            pass  # log_fail throws an exception on purpose
    else:
        try:
            with Timeout(run_timeout):
                thrower.run()
        except TimeoutError:
            try:
                thrower.log_fail('pov timed out')
                thrower.kill_procs()
            except TestFailure:
                thrower.kill_procs()
                # this exception should always happen.  don't stop because
                # one timed out.
                pass
        thrower.dump()

    return thrower.passed, thrower.failed, thrower.logs, [x.returncode for x in thrower.procs]


def main():
    """ Parse and Throw the POVs """
    parser = argparse.ArgumentParser(description='Send CGC Polls and POVs')
    required = parser.add_argument_group(title='required arguments')
    required.add_argument('--cbs', nargs='+', required=True,
                          help='List of challenge binaries to run on the server')
    required.add_argument('files', metavar='xml_file', type=str, nargs='+',
                          help='POV/Poll XML file')
    parser.add_argument('--concurrent', required=False, type=int, default=1,
                        help='Number of Polls/POVs to throw concurrently')
    parser.add_argument('--timeout', required=False, type=int, default=None,
                        help='Connect timeout')
    parser.add_argument('--munge_seed', required=False, action='store_true',
                        default=False, help='Bit invert the seed for testing')
    parser.add_argument('--failure_ok', required=False, action='store_true',
                        default=False,
                        help='Failures for this test are accepted')
    parser.add_argument('--id',dest='id',required=False, type=str, help="id for pickle content to store test info")
    parser.add_argument('--debug', required=False, action='store_true',
                        default=False, help='Enable debugging output')
    parser.add_argument('--perf', required=False, action='store_true',
                        default=False, help='Capture run-time performance for CB')
    parser.add_argument('--negotiate', required=False, action='store_true',
                        default=False, help='The CB seed should be negotiated')
    parser.add_argument('--cb_seed', required=False, type=str,
                        help='Specify the CB Seed')

    parser.add_argument('--replay', required=False, action='store_true',
                        default=False, help='generate replay.log and replay.out.log')

    parser.add_argument('--dbi', required=False, type=str, default=None, 
    help='Specify any dynamic binary instrumentation (like valgrind) to be prepended to executable under test\
    e.g. --dbi "/usr/bin/valgrind --tool=callgrind --log-file=tramp.cg.log --callgrind-out-file=tramp.cg.out"')


    args = parser.parse_args()
    if args.debug:
        print(f"Running {args.cbs} in debug mode")
    if args.id:
        enable_json_dump()

    global gen_rep_log
    gen_rep_log[0]=args.replay
    if gen_rep_log[0]:
        o=open(gen_rep_log[1],"wb")
        o.close()
        o=open(gen_rep_log[2],"wb")
        o.close()
        o=open(gen_rep_log[3],"wb")
        o.close()


    assert args.concurrent > 0, "Conccurent count must be less than 1"

    if args.cb_seed is not None and not args.negotiate:
        raise Exception('CB Seeds can only be set with seed negotiation')

    povs = []
    for pov_filename in args.files:
        pov_xml = []
        if pov_filename.endswith('.xml'):
            with open(pov_filename, 'rb') as pov_fh:
                pov_xml.append(pov_fh.read())
        elif pov_filename.endswith('.zip'):
            with zipfile.ZipFile(pov_filename, 'r') as pov_fh:
                for filename in pov_fh.namelist():
                    pov_xml.append(pov_fh.read(filename))
        else:
            raise Exception('unknown POV format')

        for xml in pov_xml:
            povs.append((xml, pov_filename))

    result_handler = Results()
    pool = mp.Pool(args.concurrent)
    pool_responses = []
    try:
        for pov in povs:
            pov_args = (args.cbs, pov, args.timeout, args.debug,
                        args.negotiate, args.cb_seed, args.munge_seed, 
                        args.dbi)
            if args.concurrent > 1:
                pool_response = pool.apply_async(run_pov, args=pov_args,
                                                 callback=result_handler.cb_pov_result)
                pool_responses.append(pool_response)
            else:
                result_handler.cb_pov_result(run_pov(*pov_args))

        for response in pool_responses:
            response.get()

    except KeyboardInterrupt:
        print("# Interrupted.  Logging as error")
        result_handler.errors += 1
        if args.concurrent > 1:
            ##pool.kill()
            #for p in pool._pool:
            #    os.kill(p.pid,signal.SIGKILL)
            #while any(p.is_alive() for p in pool._pool):
            #    pass
            pool.terminate()
    finally:
        if args.concurrent > 1:
            pool.close()
            pool.join()

    print("# total tests passed: %d" % result_handler.passed)
    print("# total tests failed: %d" % result_handler.failed)
    print("# polls passed: %d" % result_handler.full_passed)
    print("# polls failed: %d" % result_handler.errors)

    json_id(args.id)
    write_json()

    if args.failure_ok:
        return 0
    else:
        return result_handler.errors != 0


if __name__ == "__main__":
    exit(main())
