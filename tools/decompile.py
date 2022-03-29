#!/usr/bin/env python3

import os, subprocess

from prdtools import elf,ghidra_decomp

r2ghidra_enabled=False
ghidra_enabled=True


def gen_target_content(prog,funcs):
    prg_path=os.path.realpath(prog)
    prg=os.path.basename(prog)
    fn=":".join(funcs)
    return f"{prg},{prg_path},{fn}"

def get_contents_of_target(target):
    targ_=None
    with open(target,"r") as f:
        targ_=f.readlines()[0]
    prg,prg_path,fn= targ_.split(',',2)
    import re
    funcs_=re.sub("::","_____",fn)
    funcs_=re.sub(":"," ",funcs_)
    funcs_=re.sub("_____","::",funcs_)
    funcs=funcs_.rstrip().split(" ")
    print(f"{fn} => {funcs}")
    return prg,prg_path,funcs

def prog_is_cpp(prog):
    cmd=f"/usr/bin/nm {prog} "+"| awk '{print $NF}'"+"| egrep -c '^_Z'"
    p = subprocess.run(cmd,capture_output=True,shell=True)
    cnt=p.stdout.decode('ascii').rstrip()
    return cnt!="0"

def ghidra_project_init(prog):
    id_=os.path.basename(prog)
    dir_=os.path.dirname(prog)
    if os.path.exists(ghidra_decomp.set_project(dir_)):
        return
    sprog=elf.strip_binary(prog)
    # adding both stripped and unstripped binaries into project
    for i in [prog,sprog]:
        ghidra_decomp.add_binary(dir_,id_,i);

def call_hexrays(prog,funcs,hexrays_path,target,decomp_out,log,extdecomp):
    ghidra,r2ghidra=extdecomp
    elf_syms=elf.elf_file(binary_path=prog,characterize=False)
    # strip binary if program has mangled strings (only way I know how to quickly determine g++)
    strip=prog_is_cpp(prog)
    if ghidra and strip:
        ghidra_project_init(prog)
    
    sym_fns=list()


    # we are just converting the input target file to use the mangled symbols for prd_multidecomp
    if os.path.exists(target):
        prg,prog,funcs=get_contents_of_target(target)
    
    for f in funcs:
        if elf_syms.is_mangled(f):
            sym_fns.append(f)
        else:
            sym=elf_syms.get_mangled_symbol(f)
            if not sym:
                print(f"ERROR: Couldn't find mangled symbol for '{f}'")
            else:
                sym_fns.append(sym)

    if len(sym_fns)==0:
        print(f"ERROR: no functions to process")
        import sys; sys.exit(-1)
    #if strip and '.strip' not in prog:
    #    prog=elf.strip_binary(prog)
    append=""
    ext_decomp=""
    if strip:
        append="--strip-binary" 
        if r2ghidra:
            r2ghidra_=os.path.dirname(os.path.realpath(__file__))+"/prdtools/r2ghidra_decomp.py"
            ext_decomp=f"--r2ghidra '{r2ghidra_} -f <SYM> -p <BIN> --stdout '"
        if ghidra:
            ghidra_=os.path.dirname(os.path.realpath(__file__))+"/prdtools/ghidra_decomp.py"
            ext_decomp=f"--r2ghidra '{ghidra_} -p {prog} -f <SYM> -b <BIN> '"


    targ=gen_target_content(prog,sym_fns)
    with open(target,"w") as wf:
        wf.write(targ)
        wf.close()

    cmd=f"python3 {hexrays_path}/prd_multidecomp_ida.py --target_list {target} --ouput_directory {decomp_out} --scriptpath {hexrays_path}/get_ida_details.py {ext_decomp} {append}"
    print(f"Calling:\n{cmd}",flush=True)
    p=None
    with open(log,"w") as o:
        p = subprocess.run(cmd,stdout=o,shell=True)
        o.close()



if __name__ == "__main__":
    import os,sys,argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-f","--func-name","--func_name",dest="funcs",
                        metavar='N',nargs="+",help="Functions to decompile",
                        type=str, required=True)
    parser.add_argument("-p","--prog",dest="prog",help="Binary program to analyze",
                        type=str, required=True)
    parser.add_argument("-i","--independent-builds",dest="indep",help="Specifies that Fn are independent runs",
                        action='store_const',const=True,default=False)
    parser.add_argument("--ghidra-only",dest="ghidra",help="gets ghidra decompilation content",
                        action='store_const',const=True,default=False)
    parser.add_argument("--hybrid-decomp",dest="hybrid",help="generate decompilation content from ghidra on hex-rays failure",
                        action='store_const',const=True,default=False)
    parser.add_argument("--debug",dest="debug",help="strip the binary before using",
                        action='store_const',const=True,default=False)
    parser.add_argument("--strip",dest="strip",help="Strip the binary before using",
                        action='store_const',const=True,default=False)
    parser.add_argument("--target-list",dest="tout",help="file with path to generate 'target_list' content",
                        type=str, default=None)
    parser.add_argument("-l","--log",dest="log",help="Logfile for decompilation output",
                        type=str, default=None)
    parser.add_argument("-o","--out",dest="out",help="Directory for decompiled source code",
                        type=str, default=None,required=False)
    parser.add_argument("-s","--hexrays-script-path",dest="hexrays",help="Directory where 'get_ida_details.py' and 'prd_multidecomp_ida.py' reside",
                        type=str, required=False)
    args=parser.parse_args()
    if args.ghidra:
        ghidra_project_init(args.prog)
        id_=os.path.basename(args.prog)
        dir_=os.path.dirname(args.prog)
        sprog=elf.strip_binary(args.prog)
        bin_=args.prog if args.strip else sprog
        for f in args.funcs:
            ghidra_decomp.ghidra_decompile(dir_,id_,bin_,f,out_="x.c",stdout=True)
    elif not args.indep:
        call_hexrays(args.prog,args.funcs,args.hexrays,args.tout,args.out,args.log,(args.hybrid,False))
    else:
        for i,fn in enumerate(args.funcs):
            target=f"{args.tout}.{i}"
            decomp_out=f"{args.out}.{i}"
            log=f"{args.log}.{i}"
            call_hexrays(args.prog,[fn],args.hexrays,target,decomp_out,log)
            

            

