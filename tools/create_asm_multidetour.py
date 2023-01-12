#!/usr/bin/env python3

# author: pdreiter
# date:   1/15/2021
# purpose: read objdump content and generate inline asm

#---------------------------------
# EXAMPLE command line(s)
#---------------------------------
#
# +++
# scenario 1: no objdump, but .so or exe file
#
# ../create_asm.py --file-to-objdump libhook.so --debug --func "cgc_list_unread_messages:cgc_bzero,cgc_strcat,cgc_itoa,cgc_puts,cgc_strlen"
#
# +++
# scenario 2: have an objdump file
#
# ../create_asm.py --objdump-log func.objdump.txt --debug --func "cgc_list_unread_messages:cgc_bzero,cgc_strcat,cgc_itoa,cgc_puts,cgc_strlen"
#

import os,copy,argparse,sys,re
from datetime import datetime
dateinfo=datetime.now().strftime("%d%m%Y%I%M%S")

scriptdir=os.path.dirname(os.path.realpath(sys.argv[0]))
default_cwd=os.path.realpath(".")
default_src=default_cwd
debug=False
default_log=None

ASM_STUB_MARKER = "/* ASM STACK {} HERE */"


def dprint(*args, **kwargs):
    if debug:
        print(*args,**kwargs)
    if default_log:
        with open(default_log,"a") as f:
            print(*args, **kwargs, file=f, flush=True)


def get_args():
    parser=argparse.ArgumentParser(description=\
        "extract inline asm for PRD from objdump")
    parser.add_argument('--json-in',dest='json',action='store',default=None, 
        help='json input file with information')
    parser.add_argument('--func',dest='fn',action='store',default=None,
        help='function info fn_to_detour:reference1,reference2')
    parser.add_argument('--file-to-objdump',dest='objdump_in',action='store',default=None,
        help='file to objdump')
    parser.add_argument('--objdump-log',dest='objdump_out',action='store',default=None,
        help='output from objdump')
    parser.add_argument('--init-fn',dest='init_fn',action='store',default="__prd_init")
    parser.add_argument('--exit-fn',dest='exit_fn',action='store',default="__prd_exit")
    parser.add_argument('--source',dest='src',action='store',default=None)
    parser.add_argument('--debug',dest='debug',action='store_const',const=True,default=False)
    parser.add_argument('--log',dest='log',action='store',default=None)
    args=parser.parse_args()
    global debug
    global default_log
    debug=args.debug
    default_log=args.log
    args.func_list = list()
    if args.fn:
        args.func_list.append(args.fn)
    if args.json:
        import json
        with open(args.json) as json_data:
            json_dict = json.load(json_data)
            json_data.close()
        l=json_dict.get('FUNCSTUB_LIST',None)
        args.detour_prefix=json_dict.get('DETOUR_PREFIX')
        if l:
            for k,x in l.items():
                args.func_list.append(x)
            #args.func_list.append(l.items())

    if len(args.func_list)==0:
        print("ERROR: Need at least one function to disasm")
        import sys; sys.exit(-1);
    if args.objdump_in and not os.path.exists(args.objdump_in):
        print("ERROR: file to objdump '{}' does not exist".format(args.objdump_in))
        import sys; sys.exit(-1);
    if args.objdump_out and not os.path.exists(args.objdump_out):
        print("ERROR: objdump log '{}' does not exist".format(args.objdump_out))
        import sys; sys.exit(-1);
    return args

def get_func_disasm(objdump_log,func):
    start_regex="<"+func+">:"
    end_regex="\s+ret\s*$"
    func_objdump_list=list()
    if os.path.exists(objdump_log):
        (start,check_last)=(0,0)
        with open(objdump_log,'r') as f:
            while True:
                line=f.readline()
                if not line:
                    print("ERROR: reached end of objdump without finding function '"+func+"'")
                    f.close();
                    sys.exit(-1);
                if re.search(start_regex,line):
                    start=1
                if check_last:
                    check_last=0
                    if re.match("\s*$",line):
                        start=0; 
                        break;
                    else:
                        start=1;
                if start and re.search(end_regex,line):
                    start=0;check_last=1;
                if start or check_last:
                    func_objdump_list.append(line);
    return func_objdump_list               

def parse_func_objdump_list(objdumplist,funcname,num_refs,init_fn,exit_fn):
    # 0 : ..<funcname>:
    # 1 : push %ebp
    # 2 : mov %esp,%ebp
    # 3 : push %ebx
    # 4 : sub $0x4,%esp
    # BUYER BEWARE - THIS IS ASSUMING 32b compilation - more work needed for 64b
    push_ebx=False
    start_index=3
    subfn_rex="<"+funcname+">"
    initfn_rex="<"+init_fn+">"
    exitfn_rex="<"+exit_fn+">"
    leave_rex="(leave|ret)\s*$"
    stack_fix1=None
    stack_fix2="add $"+hex(4*num_refs)+",%esp"
    strip_rex="^\s*[a-fA-F0-9]+:\s+([a-f0-9]{2}\s+)+(.*)$"
    nop='"nop\\n\\t"'
    asm_array=['"pop %ebp\\n\\t"','"pop %ecx\\n\\t"',
                '"'+stack_fix2+'\\n\\t"','"push %ecx\\n\\t"','"ret\\n\\t"'];

    if not ( re.search("push\s+\%ebp",objdumplist[1]) and
             re.search("mov\s+\%esp,\%ebp",objdumplist[2]) ):
        print("ERROR: We have an unorthodox function entry")
        sys.exit(-1);
    if re.search("push\s+\%ebx",objdumplist[3]):
        push_ebx=True
        asm_array=[nop,'"pop %ebx\\n\\t"']+asm_array;
        start_index+=1
    asm_end=list()
    collect=False
    stck1= re.search("(sub\s+\$0x\d+,\%esp)",objdumplist[start_index])
    if stck1:
        stack_fix1= stck1.group(1).replace("sub","add")
        asm_array=[nop,'"'+stack_fix1+'\\n\\t"']+asm_array;
        #try:
        #    asm_array=[stack_fix1+"\\n\\t"]+asm_array;
        #except Exception as e:
        #    print("exception:"+str(asm_array));
    for i,j in enumerate(objdumplist[start_index+1:]):
        if re.search(subfn_rex,j):
            dprint("Found subfunction call: "+j)
        if re.search(initfn_rex,j):
            dprint("Found init function call: "+j)
        if re.search(exitfn_rex,j):
            dprint("Found exit function call: "+j)
            collect=True
        if re.search(leave_rex,j):
            dprint("Found end of function: "+j)
            collect=False
        if collect:
            if "add " in j or "pop " in j or "popl " in j:
                continue
            if not re.search(exitfn_rex,j):
                m=re.search(strip_rex,j)
                if m:
                    asm_end.append('"'+m.group(2)+'\\n\\t"')
    asm_array=asm_end+asm_array
    asm_array=["asm("]+asm_array+[");"]
    dprint("In-line assembly for compilation:")
    for x in asm_array:
        print(x)
    return asm_array



args=get_args();
srcf="{}.orig".format(args.src)
if not os.path.exists(srcf):
    import shutil
    shutil.copyfile(args.src,srcf)
    
dumpfile="/tmp/"+os.path.basename(args.src).split('.',1)[0]+"_"+dateinfo
if args.objdump_out and os.path.exists(args.objdump_out):
    dumpfile=args.objdump_out

for args_fn in args.func_list:
    print("{} : {}".format(type(args_fn),args_fn))
    mfunc=re.match("(\w+)(:(((\w+),)*(\w+))),?$",args_fn)
    func=args_fn
    ref_list=[];
    if mfunc:
        func=mfunc.group(1);
        if mfunc.group(3):
            ref_list=mfunc.group(3).split(',');
    
    dprint("Searching for function <"+func+">"+str(ref_list))
    
    from prdtools import elf
    elf_libhook = elf.elf_file(binary_path=args.objdump_in,symbol_info=False,debug=False)
    if  ( not os.path.exists(dumpfile) and 
       args.objdump_in and os.path.exists(args.objdump_in) ) :
        import subprocess,shlex
        proc = subprocess.Popen(shlex.split("objdump -D "+args.objdump_in),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cout,cerr=proc.communicate()
        if proc.returncode:
            print("Error when performing 'objdump -D {}'".format(args.objdump_in))
            print(cerr.decode('ascii'))
            print("Exiting.")
            sys.exit(-1)
        with open(dumpfile,'w') as f:
            f.write(cout.decode('ascii'))
            f.close()
       
    detour_func="{}{}".format(args.detour_prefix,func)
    obj_list=get_func_disasm(dumpfile,detour_func)
    asm=parse_func_objdump_list(obj_list,func,len(ref_list),args.init_fn,args.exit_fn)
    # this part leveraged from HJ's ASM_Fitter python
    if args.src:
        if not os.path.exists(args.src):
            print("ERROR: Source file indicated '"+args.src+"' does not exist!")
            print("Check your path.")
            print("Exiting.")
            sys.exit(-1);
        # Replace ASM content in source file
        lines = None
        with open(args.src) as src:
            lines = src.read()
            src.close()
        fn_ASM_STUB_MARKER = ASM_STUB_MARKER.format(func)
        if func=="main":
            fn_ASM_STUB_MARKER = ASM_STUB_MARKER.format("patchmain")
        replace = lines.replace(fn_ASM_STUB_MARKER, "\t"+"\n".join(asm))
        with open(os.path.realpath(args.src),"w") as out:
            out.write(replace)
            out.close()
            
os.remove(dumpfile)
