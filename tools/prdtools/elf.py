#!/usr/bin/env python3

# author: pdreiter
# date:   1/15/2021

#---------------------------------
# EXAMPLE command line(s)
#---------------------------------
#
import subprocess,re

def strip_binary(binary,out=None):
    import subprocess
    b_out=out
    if not out:
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



class elf_file:
    def __init__(self,binary_path=None,symbol_info=False,debug=False,characterize=True):
        self.bin=None
        self.exe=None
        self.syms=None
        self.demangled_syms_lut=None
        self.mangled_syms_lut=None
        self.local_symbols=None
        self.bin_objdump = None
        self.characterize=None
        self.debug=debug
        self.failed_syms=None
        self.binutils_version=float(subprocess.check_output(['ld','-v']).decode('ascii').rstrip().split(' ')[-1])
        # these aren't allocated in ELF exes
        self.bad_syms=['__init_array_start','__init_array_end']
        #self.binutils_version=0
        if binary_path:
            self.bin=binary_path
            import os
            self.exe=os.path.basename(self.bin)
            self.syms,self.demangled_syms_lut,self.mangled_syms_lut=self.get_symbols()
            local_syms=set([ x['name'] for s in ['t','T'] if s in self.syms.keys() for x in self.syms[s] ])
            self.local_symbols= [(x,self.demangled_syms_lut[x]) for x in list(local_syms)]
            #print("SYMBOLS: {}".format(str(" ".join(self.local_symbols))))
            self.characterize=dict()
            self.dprint("{:30s} {:20s} {:20s} {:20s}".format("Function","Num instrs","Num bytes","Num Calls"))
            self.dprint("{:30s} {:20s} {:20s} {:20s}".format("-"*30,"-"*20,"-"*20,"-"*20))
            self.failed_syms=list()
            if characterize:
                self.characterize_symbols()

    
    def characterize_symbols(self):
        """
        note this is specific to 32b ELF files (see {8} in start re.match)
        """
        for f,dmf in self.local_symbols:
            import sys
            print("- {}".format(f),file=sys.stderr)
            objdump=self.obtain_fn_objdump(f)
            if not objdump:
                self.failed_syms.append((f,dmf))
                continue
            elif len(objdump)<1:
                import sys
                print("ERROR: Can't find objdump for {}".format(f),file=sys.stderr)
                self.failed_syms.append(f)
                continue
            start=re.match("^([0-9a-fA-F]{8})\s+<(.+)>",objdump[0])
            end_re=re.compile(r"^\s*([0-9a-fA-F]{1,8}):")
            index=len(objdump)-1
            while (not end_re.search(objdump[index])) and index>0:
                index=index-1
            end=re.match("^\s*([0-9a-fA-F]{1,8}):\s+(([0-9a-fA-F]{2} )+)",objdump[index])
            try:
                start_address=int(start.group(1),16)
            except Exception as e:
                import sys
                print(e,file=sys.stderr)
                print("objdump[0] = {}".format(objdump[0]),file=sys.stderr)
                raise
            try:
                end_address=int(end.group(1),16)+len(end.group(2).rstrip().rsplit(' '))-1
            except Exception as e:
                import sys
                print(e,file=sys.stderr)
                print("objdump[{}] = {}".format(index,objdump[index]),file=sys.stderr)
                raise
            self.characterize[f] = { 
                                     'demangled_name':dmf,
                                     'num_instructions':len(objdump)-1,
                                     'num_calls':len([x for x in objdump if "\tcall " in x]),
                                     'num_bytes':end_address-start_address,
                                     'offset':start_address,
                                     #'objdump':objdump
                                   }
            self.dprint("{:30s} {:20s} {:20s} {:20s}".format(f,str(len(objdump)),str(self.characterize[f]['num_bytes']),str(self.characterize[f]['num_calls'])))
    
    def is_mangled(self,mangled:str):
        return mangled in list(self.demangled_syms_lut.keys())
            
    def is_demangled(self,demangled:str):
        return demangled in list(self.mangled_syms_lut.keys())

    def demangled(self):
        return list(self.mangled_syms_lut.keys())
            
    def mangled(self):
        return list(self.demangled_syms_lut.keys())
            
            
    def get_demangled_symbol(self,mangled:str):
        search_re=re.compile(r"\b"+f"{mangled}"+r"\b")
        for dm in self.demangled_syms_lut.keys():
            if search_re.match(dm):
                return self.demangled_syms_lut[dm]
        return None

    def get_mangled_symbol(self,demangled:str):
        search_re=re.compile(r"\b"+f"{demangled}"+r"\b")
        for dm in self.mangled_syms_lut.keys():
            if search_re.match(dm):
                return self.mangled_syms_lut[dm]
        return None
            
            
    def dprint(self,*args, **kwargs):
        if self.debug:
            print(*args,**kwargs)

    def get_functions_min_bytes(self,min_bytes):
        min_set=set()
        for fn in self.characterize.keys():
            if int(self.characterize[fn]['num_bytes'])>=int(min_bytes):
                f=(fn,self.characterize[fn]['demangled_name'])
                min_set.add(f)
        return min_set

    def get_functions_min_instr(self,min_instr):
        min_set=set()
        for fn in self.characterize.keys():
            if int(self.characterize[fn]['num_instructions'])>=int(min_instr):
                f=(fn,self.characterize[fn]['demangled_name'])
                min_set.add(f)
        return min_set

    def load_json(self,json_inf):
        import json
        with open(json_inf) as json_data:
            x=json.load(json_data)
            json_data.close()
        self.bin=x['bin']
        self.exe=x['exe']
        self.failed_syms=x['failed_symbols']
        self.syms=x['symbols']
        self.local_symbols=x['locals']
        self.characterize=x['info']
        self.mangled_syms_lut=x['mangled_lut']
        self.demangled_syms_lut=x['demangled_lut']
        #self.bin_objdump=x['objdump']


    def dump_json(self,json_outf):
        x={'bin':self.bin,
           'exe':self.exe,
           'failed_symbols':self.failed_syms,
           'symbols':self.syms,
           'locals':self.local_symbols,
           'info':self.characterize,
           'mangled_lut':self.mangled_syms_lut,
           'demangled_lut':self.demangled_syms_lut,
           }
        with open(json_outf,'w') as outFile:
            import json
            json.dump(x,outFile)
            outFile.close()

    def obtain_objdump(self):
        #cmd=["/usr/bin/objdump","-D","-C",self.bin]
        cmd=["/usr/bin/objdump","-D",self.bin]
        proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cout,cerr=proc.communicate()
        if proc.returncode:
            import sys
            print("Error when performing 'objdump -D {}'".format(self.bin),file=sys.stderr)
            print(cerr.decode('ascii'),file=sys.stderr)
            print("Exiting.",file=sys.stderr)
            sys.exit(-1)
        return cout.decode('ascii')

    def get_symbols(self):
        #cmd=["/usr/bin/nm","--demangle",self.bin]
        cmd=["/usr/bin/nm",self.bin]
        symproc=subprocess.Popen(" ".join(cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
        #ret=symproc.poll()
        #if ret == None:
        #    ret=symproc.poll()
        #    print("Error running '{}' {} ".format(" ".join(cmd),ret))
        #    return None
        sout,serr = symproc.communicate()
        output=sout.decode('ISO-8859-1')
        lines=output.split('\n')
        self.dprint(lines[0])
        symbol_dict = dict()
        demangled_syms=dict()
        mangled_syms=dict()
        for x in lines:
            if len(x)<13:
                self.dprint(x)
                continue
            self.dprint(x)
            symadd=x[0:8]
            symtype=x[9:10]
            symname=x[11:len(x)]
            if x[8]!=" ":
                print("ERROR!! Looks like a 64b binary\nExiting.")
                import sys;sys.exit(-1);
                
                
            ltype=symbol_dict.get(symtype,None)
            if not ltype:
                symbol_dict[symtype]=list()
            x=symname.rstrip()
            if x in self.bad_syms or len(x)<1:
                continue
            cmd=["/usr/bin/c++filt",x]
            self.dprint(f"{cmd}")
            out = subprocess.check_output(" ".join(cmd),shell=True)
            dem = out.decode('ascii').rstrip()
            self.dprint(f"{symtype} : {symname} => {dem}")
            symbol_dict[symtype].append({'name':symname,'address':symadd,'type':symtype,'demangled':dem})
            mangled_syms[dem]=symname
            demangled_syms[symname]=dem
        return symbol_dict,demangled_syms,mangled_syms

    def get_func_disasm(self,objdump,func):
        start_regex="<"+func+">:"
        end_regex="(\s+ret\s*$|\.\.\.)"
        func_objdump_list=list()
        objdump_log = objdump.split('\n')
        if len(objdump_log)>0:
            (start,check_last)=(0,0)
            i=0; found=False
            #with open(objdump_log,'r') as f:
            while i<len(objdump_log) and not found:
                line=objdump_log[i]; 
                i+=1;
                #if not line:
                #    print("ERROR: reached end of objdump without finding function '"+func+"'")
                #    #f.close();
                #    #sys.exit(-1);
                if re.search(start_regex,line):
                    start=1
                if check_last:
                    check_last=0
                    if re.match("\s*$",line):
                        start=0; 
                        found=True
                        break;
                    else:
                        start=1;
                if start and re.search(end_regex,line):
                    start=0;check_last=1;
                if start or check_last:
                    func_objdump_list.append(line);
        return func_objdump_list               

    def obtain_fn_objdump(self,fn_):
        fn=f"'{fn_.rstrip().lstrip()}'"

        #if "::" in fn:
        #    print(f"[WARNING] currently not supporting C++ functions like '{fn}'")
        #    return None
        if self.binutils_version<2.32:
            if not self.bin_objdump:
                self.bin_objdump = self.obtain_objdump()
            return self.get_func_disasm(self.bin_objdump,fn)
        else:
            disasm_fn=f"--disassemble={fn}"
            #objdump_cmd=["/usr/bin/objdump","-D","-C", disasm_fn,self.bin]
            objdump_cmd=["/usr/bin/objdump","-D",disasm_fn,self.bin]
            egrep_cmd=["egrep","-v","'(Disassembly|file format|^$)'"]
            cmd=objdump_cmd+["|"]+egrep_cmd
            dump=None
            try:
                out = subprocess.check_output(" ".join(cmd),shell=True)
                dump=out.decode("ascii").split('\n')
            except Exception as e:
                if type(e)==subprocess.CalledProcessError:
                    dump=""
                    pass
                else:
                    raise(e)
            #print(dump[0:5])
            return dump


def get_min_set(elf_info:elf_file,min_inst,min_bytes,min_AND:bool=False):
    x,x1,x2=(None,None,None)
    if min_inst:
        x1=elf_info.get_functions_min_instr(min_inst)
        x=x1
    if min_bytes:
        x2=elf_info.get_functions_min_bytes(min_bytes)
        if min_AND and x1:
            x=x1 & x2
        elif x1:
            x=x1 | x2
        else:
            x=x2
    return x


