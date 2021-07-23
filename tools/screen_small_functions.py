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

import subprocess
from prdtools import elf


if __name__ == "__main__":
    
    import os,copy,argparse,sys,re
    from datetime import datetime
    dateinfo=datetime.now().strftime("%d%m%Y%I%M%S")
    
    scriptdir=os.path.dirname(os.path.realpath(sys.argv[0]))
    default_cwd=os.path.realpath(".")
    default_src=default_cwd
    debug=False
    default_log=None
    
    def dprint(*args, **kwargs):
        if debug:
            print(*args,**kwargs)
        if default_log:
            with open(default_log,"a") as f:
                print(*args, **kwargs, file=f, flush=True)
    
    
    def get_args():
        parser=argparse.ArgumentParser(description=\
            "extract executable information from objdump")
        parser.add_argument('--json-in',dest='json_in',action='store',default=None, 
            help='json file to get ELF information')
        parser.add_argument('--instr-min',dest='min_inst',action='store',default=None, 
            help='minimum number of instructions a function requires to be outputted')
        parser.add_argument('--byte-min',dest='min_bytes',action='store',default=None, 
            help='minimum number of bytes a function requires to be outputted')
        parser.add_argument('--no-sym-info',dest='sym_info',action='store_false',default=True,
            help="Obtain symbols but do not extract symbol information (no objdump)")
        parser.add_argument('--AND-min',dest='min_AND',action='store_true',default=False,
            help='Need to satisfy both minimum number of bytes and instructions for a function to be outputted')
        parser.add_argument('--json-out',dest='json',action='store',default=None, 
            help='json output file to store ELF information')
        parser.add_argument('--exe',dest='exe',action='store',default=None,
            help='file to objdump')
        parser.add_argument('--debug',dest='debug',action='store_const',const=True,default=False)
        args=parser.parse_args()
        return args
    args=get_args();
    if args.exe:
        myINFO=elf.elf_file(args.exe,args.sym_info,args.debug)
        if args.json:
            myINFO.dump_json(args.json)
        if not args.sym_info:
            import sys; sys.exit(0)
    if args.json_in:
        myINFO=elf.elf_file()
        myINFO.load_json(args.json_in)
        # not sure what to do with this, but sure, okay
         
    x=elf.get_min_set(elf_info=myINFO,min_inst=args.min_inst,min_bytes=args.min_bytes,min_AND=args.min_AND)
    if x:
        for i,dmf in x:
            p=f"[{i}]:[{dmf}]"
            print(p)
