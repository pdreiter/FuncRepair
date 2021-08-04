#!/usr/bin/env python3

import os,re,subprocess,tempfile

#GHIDRA_HEADLESS="/home/bss-lab-1/research/ghidra_10.0.1_PUBLIC/support/analyzeHeadless"
GHIDRA_HEADLESS=os.environ.get("GHIDRA_HEADLESS")
MYSCRIPTDIR=os.path.dirname(__file__);
import_cmd=f"{GHIDRA_HEADLESS} <PROJ_DIR>  <PROJ_NAME> -import <BIN>"

decomp_cmd=f"{GHIDRA_HEADLESS} <PROJ_DIR> <PROJ_NAME> -process <BIN> -scriptpath {MYSCRIPTDIR} -postScript ghidra_prd.java <SYMBOL> <C_OUT>"

def set_project(dir_):
    return dir_+"/ghidra_proj"

def clean_code(decomp):
    i__=decomp.split('\n');
    o__=list()
    for in_ in i__:
        out=re.sub(r"\b__thiscall\b",r"",in_);
        out=re.sub(r"\bundefined4\b",r"uint32_t",out);
        if "x86.get_pc_thunk" in out:
            #out=re.sub(r"^(\s+)",r"\1//",out)
            pass
        else:
            o__.append(out)
    return "\n".join(o__)



def add_binary(dir_,id_,bin_):
    d=set_project(dir_);
    if not os.path.exists(d):
        os.makedirs(d);

    # for un-stripped binaries, id_==bin_, else bin_ is the stripped binary name, id_ is original binary (project)
    # -process <BIN> needs the basename, since we've already imported
    cmd=re.sub(r"<PROJ_DIR>",d,import_cmd);
    cmd=re.sub(r"<PROJ_NAME>",id_,cmd);
    cmd=re.sub(r"<BIN>",bin_,cmd);
    p=subprocess.run(cmd,shell=True)
    if p.returncode!=0:
        print(f"ERROR: Importing a binary into Ghidra project failed!");
        print(f"cmd => '{cmd}'");
        import sys; sys.exit(-1);

def ghidra_decompile(dir_,id_,bin_,symbol,out_,stdout):
    f=out_
    d=os.path.basename(dir_);
    i=os.path.basename(id_);
    b=os.path.basename(bin_);
    t=None
    prefix=f"{d}-{i}-{b}-{symbol}"
    if not out_:
        t=tempfile.NamedTemporaryFile(mode='r',dir="/tmp",prefix=f"{prefix}.c.", delete=True);
        f=t.name
    d=set_project(dir_);
    cmd=re.sub(r"<PROJ_DIR>",d,decomp_cmd);
    cmd=re.sub(r"<PROJ_NAME>",id_,cmd);
    cmd=re.sub(r"<BIN>",b,cmd);
    cmd=re.sub(r"<SYMBOL>",symbol,cmd);
    cmd=re.sub(r"<C_OUT>",f,cmd);
    ghidra_log=f"ghidra.{prefix}.log"
    fstdout=open(ghidra_log,"w");
    p=subprocess.run(cmd,stdout=fstdout,stderr=subprocess.STDOUT,shell=True)
    if t:
        x=clean_code(t.read())
        print(x)
    elif stdout:
        print_decomp(f)
        

def print_decomp(dfile):
    x=""
    with open(dfile,'r') as f:
        x=clean_code(f.read());
        f.close();
    print(x)
    


if __name__ == "__main__":
    import os,sys,argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-f","--func-name","--func_name",dest="funcs",
                        metavar='N',nargs="+",help="Functions to decompile",
                        type=str, required=True)
    parser.add_argument("-p","--prog",dest="prog",help="Binary program to analyze",
                        type=str, required=True)
    parser.add_argument("--debug",dest="debug",help="debug information",
                        action='store_const',const=True,default=False)
    parser.add_argument("--target-list",dest="tout",help="file with path to generate 'target_list' content",
                        type=str, default=None)
    parser.add_argument("--no-stdout",dest="stdout",help="Don't redirect output to STDOUT",
                        action='store_const', const=False, default=True)
    parser.add_argument("-c","--c-out",dest="c_out",help="output file for C content",
                        type=str, default=None)
    #parser.add_argument("-p","--proj-dir",dest="pdir",help="Ghidra project dir",
    #                    type=str, default=None)
    #parser.add_argument("-n","--proj-name",dest="pname",help="Ghidra project name",
    #                    type=str, default=None)
    parser.add_argument("-b","--bin",dest="bin",help="Binary to decompile with Ghidra",
                        type=str, default=None)
    args=parser.parse_args()
        
    pdir=os.path.dirname(args.prog)
    pname=os.path.basename(args.prog)
    for f in args.funcs:
        d=ghidra_decompile(pdir,pname,args.bin,f,args.c_out,args.stdout)



