#!/usr/bin/env python3

import r2pipe
import re

def get_r2syms(sym_out,debug=False):
    sym_=sym_out.split("\n")
    lut=dict()
    for i in sym_:
        i_ = i.split()
        if len(i_)>0:
            if re.match("0x\d+",i_[0]):
                translt=i_[2]
                if "::" in translt:
                    translt=re.sub(r"\bsym.",r"method.",translt)
                    translt=re.sub("::",r".",translt)
                lut[i_[0]]={'orig':i_[2],'translated':translt}
                if debug:
                    print(f"{i} \n => address: {i_[0]} , symbol : {lut[i_[0]]}")
            else:
                #print(f" no match: {i}")
                pass
    return lut

def get_aflllut(afll_out,debug=False):
    afll_=afll_out.split("\n")
    lut=dict()
    for i in afll_:
        i_ = i.split()
        if len(i_)>0:
            if re.match("0x\d+",i_[0]):
                lut[i_[0]]=" ".join(i_[14:])
                if debug:
                    print(f"{i} \n => address: {i_[0]} , symbol : {lut[i_[0]]}")
            else:
                #print(f" no match: {i}")
                pass
    return lut

def get_islut(is_out,debug=False):
    is_=is_out.split("\n")
    lut=dict()
    for i in is_:
        i_ = i.split()
        if len(i_)>6:
            if re.match("\d+",i_[0]):
                name=" ".join(i_[6:])
                if debug:
                    print(f"{i} "+"\n"+f"=> {name}")
                lut[i_[0]]={'name':" ".join(i_[6:]),"paddr":i_[1],"vaddr":i_[2]}
        else:
            #print(f"Problem with line '{i}'")
            pass
    return lut

def get_mangledsym_lut(r2):
    r2.cmd(f"aaaa")
    r2.cmd(f"afta")
    r2_funcs=r2.cmd(f"afll")
    #print(f" => {r2_funcs}")
    r2.cmd(f"e bin.demangle=false")
    o_mangled=r2.cmd("is")
    r2.cmd(f"e bin.demangle=true")
    o_demangled=r2.cmd("is")
    r2.cmd(f"fs symbols")
    r2_syms=r2.cmd(f"f")
    addr2rsym=get_r2syms(r2_syms)
    mang=get_islut(o_mangled)
    demang=get_islut(o_demangled)
    #addr2rsym=get_aflllut(r2_funcs)
    m=get_aflllut(r2_funcs)
    mangLUT=dict()
    rsym2demang=dict()
    for i in mang.keys():
        addr=mang[i]['paddr']
        
        r2sym=addr2rsym.get(addr,None) #[mang[i]['paddr']]
        if not r2sym:
            #print(f"Problem with address {addr}")
            continue
        
        #print(f"Found address {addr}")
        val=r2sym
        if type(r2sym)==dict:
            val=r2sym['translated']
        mangLUT[mang[i]['name']]={'demangled':demang[i],'r2sym':val}
        rsym2demang[val]=demang[i]
        
    return mangLUT,rsym2demang

def translate_r2ghidra(symlut,d_in):
    k="|".join(list(symlut.keys()))
    syms_re=re.compile(r"\b("+k+r")\b")
    lines=d_in.split('\n')
    updated=list()
    for l in lines:
        l=re.sub(r"\bundefined4\b",r"uint32_t",l)
        l=re.sub(r"\bdbg\.","",l)
        if re.match(r"\s*fcn\.[\da-fA-f]{8}\(\)",l):
            continue
        if "__x86.get_pc_thunk" in l:
            continue
        x=syms_re.search(l)
        if x:
            replaceme=x.group(1)
            demsym=symlut[replaceme]['name']
            demang=demsym.split('(',1)[0]
            l=re.sub(r"\b"+replaceme+r"\b",demang,l)
        updated.append(l)
    return "\n".join(updated)
    pass

def open_r2pipe(p_name):
    return r2pipe.open(p_name)

def close_r2pipe(r2):
    # the following hangs the python script
    #return r2.quit()
    return

def get_gsyms(r2):
    pass

def get_demanged_symbol(f_name,mangLUT):
    return mangLUT[f_name]['demangled']

def get_function_symbol(f_name,mangLUT):
    #print(f"{f_name} => {mangLUT[f_name]}")
    return mangLUT[f_name]['r2sym']

def get_decomp_func(r2,fsym):
    # don't need to seek if I do pdg @
    r2.cmd(f"s {fsym}") # seek to function symbol
    r2.cmd("aaaa") # analyze
    d=r2.cmd(f"pdg @{fsym}")
    return d


def strip_binary(binary):
    import subprocess
    b_out=f"{binary}.strip"
    x=subprocess.run(f"cp {binary} {b_out}",shell=True)
    if x.returncode!=0:
        print(f"[WARNING!] Failed to create {b_out} from binary source.\nSkipping stripping of symbols")
        b_out=binary
    else:
        x=subprocess.run(f"/usr/bin/strip --strip-all {b_out}",shell=True)
        if x.returncode!=0:
            print(f"[WARNING!] Failed to strip symbols from {b_out}!")
            print(f"Reverting to original binary")
            b_out=binary
    return b_out


if __name__ == "__main__":
    import os,sys,argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-f","--func-name","--func_name",dest="func",
                        metavar='N',nargs="+",help="Functions to decompile",
                        type=str, required=True)
    parser.add_argument("-p","--prog",dest="prog",help="Binary program to analyze",
                        type=str, required=True)
    parser.add_argument("--debug",dest="debug",help="strip the binary before using",
                        action='store_const',const=True,default=False)
    parser.add_argument("--no-strip",dest="strip",help="Don't strip the binary before using",
                        action='store_const',const=False,default=True)
    parser.add_argument("-o","--out",dest="out",help="Filename for decompiled source code",
                        type=str, default=None)
    args=parser.parse_args()

    binary=args.prog
    if not args.out:
        args.out=f"{os.path.basename(binary)}_gdecomp.c"
    # NOTE : problem with unstripped binaries and symbol look-up
    if args.strip:
        binary=strip_binary(binary)
    
    d=list()
    r2=open_r2pipe(binary)
    mangled_lut,rsym_to_demangled=get_mangledsym_lut(r2)
    for f in args.func:
        fsym=get_function_symbol(f,mangled_lut)
        #print(f"Found symbol for {f} => {fsym}")
        d.append(get_decomp_func(r2,fsym))
    print("Decompilation done!")

    d_out="\n\n".join(d)
    if args.debug:
        with open(args.out+".tmp","w") as f:
            f.write(d_out)
            f.close()
    d_out=translate_r2ghidra(rsym_to_demangled,d_out)
    with open(args.out,"w") as f:
        f.write(d_out)
        f.close()

    close_r2pipe(r2)
    
                       

