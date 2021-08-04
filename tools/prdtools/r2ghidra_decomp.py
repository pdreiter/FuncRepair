#!/usr/bin/env python3.7

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
                if debug:
                    print(f" no match: {i}")
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
    print(f"length => {len(is_)}")
    lut=dict()
    for j,i in enumerate(is_):
        i_ = i.split()
        if len(i_)>6:
            if re.match("\d+",i_[0]):
                name=" ".join(i_[6:])
                lut[i_[0]]={'name':" ".join(i_[6:]),"paddr":i_[1],"vaddr":i_[2]}
                if debug:
                    print(f"{i} "+"\n"+f"=> '{name}'")
                if i_[0]=="84":
                    print(f"{i} "+"\n"+f"=> '{name}'")

        else:
            print(f"Problem with line '{i}'")
            pass
    #print(f"Processed {j} entries")
    #for i,x in lut.items():
    #    print(x['name'])
    return lut

def get_mangledsym_lut(o_mangled,o_demangled,r2_syms,r2_funcs):
    #print(f" => {r2_funcs}")
    os=o_mangled.split("\n")
    print(f"length => {len(os)}")
    #for i,l in enumerate(os[-25:]):
    #    print(f"{i} : {l}")
    # this kinda works for stripped binaries
    #addr2rsym=get_r2syms(r2_syms,True)
    import copy
    mang=copy.deepcopy(get_islut(o_mangled))
    #print("==========================")
    demang=copy.deepcopy(get_islut(o_demangled))
    print("DEMANGLED:")
    #keys are numbers, values are dicts
    for i,k in demang.items():
        x=mang.get(i,None)
        if not x:
            print(f"doesn't exist in mang => {i} [ {k} ]")
        else:
            #print(f"[{i}] mangled: {x['name']}, demangled: {k['name']}")
            pass
    addr2rsym=get_aflllut(r2_funcs)
    #m=get_aflllut(r2_funcs)
    mangLUT=dict()
    rsym2demang=dict()
    for i in mang.keys():
        addr=mang[i]['paddr']
        
        r2sym=addr2rsym.get(addr,None) #[mang[i]['paddr']]
        if not r2sym:
            #print(f"Problem with address {addr}")
            continue
        
        val=r2sym
        if type(r2sym)==dict:
            val=r2sym['translated']
        print(f"Found address {addr} [mangled name = {mang[i]['name']} => {val}")
        mangLUT[mang[i]['name']]={'demangled':demang[i],'r2sym':val}
        rsym2demang[val]=demang[i]
        
    return mangLUT,rsym2demang

def translate_r2ghidra(symlut,d_in,enable_prd=False):
    k="|".join(list(symlut.keys()))
    syms_re=re.compile(r"\b("+k+r")\b")
    lines=d_in.split('\n')
    updated=list()
    for l in lines:
        l=re.sub(r"\bundefined4\b",r"uint32_t",l)
        if re.search(r"\s*fcn\.[\da-fA-f]{8}\(\)",l):
            l=re.sub(r"^(\s+)",r"\1//",l)
            #continue
        if "__x86.get_pc_thunk" in l:
            l=re.sub(r"^(\s+)",r"\1//",l)
            #continue
        x=syms_re.search(l)
        if x:
            replaceme=x.group(1)
            demsym=symlut[replaceme]['name']
            demang=demsym.split('(',1)[0]
            l=re.sub(r"\b"+replaceme+r"\b",demang,l)
        if enable_prd:
            l=re.sub(r"::","__",l)
        l=re.sub(r"\bdbg\.","",l)
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
    print(f"{f_name}")
    print(f"===> {' '.join(mangLUT.keys())}")
    print(f"=> '{mangLUT[f_name]}'")
    return mangLUT[f_name]['r2sym']

def get_decomp_func(r2,fsym):
    # don't need to seek if I do pdg @
    r2.cmd(f"s {fsym}") # seek to function symbol
    r2.cmd("aaaa") # analyze
    d=r2.cmd(f"pdg @{fsym}")
    #d=r2.cmd(f"pdg")
    return d

def get_func_prototype(r2,fsym):
    #print(f"looking for {fsym}")
    x=get_decomp_func(r2,fsym)
    d=x.split("\n"); i=0
    while re.match(r"^(\s*|\s*\/\/.*)$",d[i]):
        #print(f"no prototype: {d[i]}")
        i+=1
    return d[i]+";\n",x

def strip_binary(binary):
    import subprocess
    b_out=f"{binary}.strip"
    x=subprocess.run(f"cp {binary} {b_out}",shell=True)
    if x.returncode!=0:
        print(f"[WARNING!] Failed to create {b_out} from binary source.\nSkipping stripping of symbols",file=sys.stderr)
        b_out=binary
    else:
        x=subprocess.run(f"/usr/bin/strip {b_out}",shell=True)
        if x.returncode!=0:
            print(f"[WARNING!] Failed to strip symbols from {b_out}!",file=sys.stderr)
            print(f"Reverting to original binary",file=sys.stderr)
            b_out=binary
    return b_out

def get_decomp_by_fn(strip,binary,func,prd,debug):
    sbin=binary
    if strip:
        sbin=strip_binary(binary)
    d=dict()
    r2=r2pipe.open(binary)
    r2.cmd(f"e bin.demangle=false")
    o_mangled=str(r2.cmd("is"))
    r2.cmd(f"e bin.demangle=true")
    o_demangled=r2.cmd("is")
    r2.cmd(f"aaaa")
    #r2.cmd(f"afta")
    #r2_funcs=r2.cmd(f"afll")
    r2.cmd(f"fs symbols")
    r2_syms=r2.cmd(f"f")
    mangled_lut,rsym_to_demangled= get_mangledsym_lut(o_mangled,o_demangled,r2_syms)
    for f in func:
        fsym=get_function_symbol(f,mangled_lut)
        #print(f"Found symbol for {f} => {fsym}")
        d_out=get_decomp_func(r2,fsym)
        d_=translate_r2ghidra(rsym_to_demangled,d_out,prd)
        d__=d_.split('\n')
        i=0
        while(re.match(r"\s*",d[i]) or re.match(r"\s*\/\/",d[i])):
            i+=1
        d[f]={'body':d_[i+1:],'proto':d[i]}
    if debug:
        import sys
        print("Decompilation done!",file=sys.stderr)
    return d


def get_required_syms(dcode,syms_re,dsym_list=None):
    lines=dcode.split('\n')
    syms=list()
    for l in lines:
        if re.match(r"\s*fcn\.[\da-fA-f]{8}\(\)",l):
            continue
        if "__x86.get_pc_thunk" in l:
            continue
        x=syms_re.search(l)
        if x:
            replaceme=x.group(1)
            if not dsym_list or replaceme not in dsym_list:
                syms.append(replaceme)
            #demsym=symlut[replaceme]['name']
            #demang=demsym.split('(',1)[0]
            #l=re.sub(r"\b"+replaceme+r"\b",demang,l)
    print(f"Found these reference symbols: {syms}",file=sys.stderr)
    return syms

def get_prototypes(binary,func,prd,debug):
    d=list()
    r2=r2pipe.open(binary)
    r2.cmd(f"e bin.demangle=false")
    o_mangled=str(r2.cmd("is"))
    r2.cmd(f"e bin.demangle=true")
    o_demangled=str(r2.cmd("is"))
    r2.cmd(f"aaaa")
    #r2.cmd(f"afta")
    r2_funcs=r2.cmd(f"afll")
    r2.cmd(f"fs symbols")
    r2_syms=r2.cmd(f"f")
    mangled_lut,rsym_to_demangled= get_mangledsym_lut(o_mangled,o_demangled,r2_syms,r2_funcs)
    k="|".join(list(rsym_to_demangled.keys()))
    syms_re=re.compile(r"\b("+k+r")\b")
    fsyms=[get_function_symbol(f,mangled_lut) for f in func]
    decomp_decl=set()
    for i,f in enumerate(func):
        #prefix="\n//----- ( "+f"{fsyms[i]}" +" ) "+"-"*50+"\n"
        proto,_decomp=get_func_prototype(r2,fsyms[i])
        #_decomp=prefix+_decomp
        #print(f"Found symbol for {f} => {fsyms[i]}"+"\nDecompilation:\n")
        #print(_decomp)
        decomp_decl.add(proto)
        req_syms=get_required_syms(_decomp,syms_re,fsyms)
        for x in req_syms:
            prototype,_d=get_func_prototype(r2,x)
            decomp_decl.add(prototype)
        d.append(_decomp)
    if debug:
        import sys
        print("Decompilation done!",file=sys.stderr)
    return decomp_decl, d, mangled_lut, rsym_to_mangled


#def get_decomp_source(strip,binary,func,prd,debug):
#    if strip:
#        print(f"stripping binary {binary}")
#        sbin=strip_binary(binary)
#        if sbin==binary:
#            # stripping failed, standard handling
#            return get_decomp_source(strip,binary,func,prd,debug)
#        else:
#            protos, decomp, mangled_lut, rsym_to_mangled=\
#               get_prototypes(binary,func,prd,debug)
#            #
#
#    else:
#        return get_decompiled_source(strip,binary,func,prd,debug)
#
#

def get_decompiled_source(strip,binary,func,prd,debug):
    #d_out,d_=get_decompiled_source(args.strip,binary,args.func,args.prd,args.debug)
    if strip:
        print(f"stripping binary {binary}")
        binary=strip_binary(binary)
        #r2=r2pipe.open(binary)
    d=list()
    r2=r2pipe.open(binary)
    r2.cmd(f"e bin.demangle=false")
    o_mangled=str(r2.cmd("is"))
    r2.cmd(f"e bin.demangle=true")
    o_demangled=str(r2.cmd("is"))
    r2.cmd(f"aaaa")
    #r2.cmd(f"afta")
    r2_funcs=r2.cmd(f"afll")
    r2.cmd(f"fs symbols")
    r2_syms=r2.cmd(f"f")
    mangled_lut,rsym_to_demangled= get_mangledsym_lut(o_mangled,o_demangled,r2_syms,r2_funcs)
    k="|".join(list(rsym_to_demangled.keys()))
    syms_re=re.compile(r"\b("+k+r")\b")
    fsyms=[get_function_symbol(f,mangled_lut) for f in func]
    decomp_decl=set()
    for i,f in enumerate(func):
        prefix="\n//----- ( "+f"{fsyms[i]}" +" ) "+"-"*50+"\n"
        proto,_decomp=get_func_prototype(r2,fsyms[i])
        _decomp=prefix+_decomp
        #print(f"Found symbol for {f} => {fsyms[i]}"+"\nDecompilation:\n")
        #print(_decomp)
        decomp_decl.add(proto)
        req_syms=get_required_syms(_decomp,syms_re,fsyms)
        for x in req_syms:
            prototype,_d=get_func_prototype(r2,x)
            decomp_decl.add(prototype)
        d.append(_decomp)
    if debug:
        import sys
        print("Decompilation done!",file=sys.stderr)
    div="\n//"+"-"*68+"\n"
    seg1=div+"// Function declarations\n\n"+"".join(list(decomp_decl))
    seg2="\n\n".join(d)
    d_out=seg1+seg2+"\n\n"+div
    d_=None
    if debug:
        import copy
        d_ = copy.copy(d_out)
    d_out=translate_r2ghidra(rsym_to_demangled,d_out,prd)
    close_r2pipe(r2)
    return d_out,d_

if __name__ == "__main__":



    import os,sys,argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-f","--func-name","--func_name",dest="func",
                        metavar='N',nargs="+",help="Functions to decompile",
                        type=str, required=True)
    parser.add_argument("-p","--prog",dest="prog",help="Binary program to analyze",
                        type=str, required=True)
    parser.add_argument("--prd",dest="prd",help="prepare decompiled output for PRD",
                        action='store_const',const=True,default=False)
    parser.add_argument("--debug",dest="debug",help="strip the binary before using",
                        action='store_const',const=True,default=False)
    parser.add_argument("--strip",dest="strip",help="Don't strip the binary before using",
                        action='store_const',const=True,default=False)
    parser.add_argument("--stdout",dest="stdout",help="output decompilation to stdout",
                        action='store_const',const=True,default=False)
    parser.add_argument("-o","--out",dest="out",help="Filename for decompiled source code",
                        type=str, default=None)
    args=parser.parse_args()

    binary=args.prog
    d_out,d_=get_decompiled_source(args.strip,binary,args.func,args.prd,args.debug)
    if args.stdout:
        print(d_out,file=sys.stdout,flush=True)
    else:
        if not args.out:
            args.out=f"{os.path.basename(binary)}_gdecomp.c"
        with open(args.out,"w") as f:
            f.write(d_out)
            f.close()
        if args.debug:
            with open(args.out+".tmp","w") as f:
                f.write(d_)
                f.close()
        
                           
    
