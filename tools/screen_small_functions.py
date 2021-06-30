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



class elf_file:
            
    def __init__(self,binary_path=None,symbol_info=False,debug=False):
        self.bin=None
        self.exe=None
        self.syms=None
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
            self.syms=self.get_symbols()
            self.local_symbols=list(set([ x['name'] for s in ['t','T'] for x in self.syms[s] ]))
            if not symbol_info:
                for l in self.local_symbols:
                    print(l)
                return
            self.characterize=dict()
            #print("SYMBOLS: {}".format(str(" ".join(self.local_symbols))))
            self.dprint("{:30s} {:20s} {:20s} {:20s}".format("Function","Num instrs","Num bytes","Num Calls"))
            self.dprint("{:30s} {:20s} {:20s} {:20s}".format("-"*30,"-"*20,"-"*20,"-"*20))
            self.failed_syms=list()
            for f in self.local_symbols:
                import sys
                print("- {}".format(f),file=sys.stderr)
                objdump=self.obtain_fn_objdump(f)
                if len(objdump)<1:
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
                                         'num_instructions':len(objdump)-1,
                                         'num_calls':len([x for x in objdump if "\tcall " in x]),
                                         'num_bytes':end_address-start_address,
                                         'offset':start_address,
                                         #'objdump':objdump
                                       }
                self.dprint("{:30s} {:20s} {:20s} {:20s}".format(f,str(len(objdump)),str(self.characterize[f]['num_bytes']),str(self.characterize[f]['num_calls'])))
    
    def dprint(self,*args, **kwargs):
        if self.debug:
            print(*args,**kwargs)

    def get_functions_min_bytes(self,min_bytes):
        min_set=set()
        for f in self.characterize.keys():
            if int(self.characterize[f]['num_bytes'])>=int(min_bytes):
                min_set.add(f)
        return min_set

    def get_functions_min_instr(self,min_instr):
        min_set=set()
        for f in self.characterize.keys():
            if int(self.characterize[f]['num_instructions'])>=int(min_instr):
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
        #self.bin_objdump=x['objdump']


    def dump_json(self,json_outf):
        x={'bin':self.bin,
           'exe':self.exe,
           'failed_symbols':self.failed_syms,
           'symbols':self.syms,
           'locals':self.local_symbols,
           'info':self.characterize,
           #'objdump':self.bin_objdump
           }
        with open(json_outf,'w') as outFile:
            import json
            json.dump(x,outFile)
            outFile.close()

    def obtain_objdump(self):
        cmd=["/usr/bin/objdump","-D","-C",self.bin]
        proc = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        cout,cerr=proc.communicate()
        if proc.returncode:
            import sys
            print("Error when performing 'objdump -D -C {}'".format(self.bin),file=sys.stderr)
            print(cerr.decode('ascii'),file=sys.stderr)
            print("Exiting.",file=sys.stderr)
            sys.exit(-1)
        return cout.decode('ascii')

    def get_symbols(self):
        cmd=["/usr/bin/nm","--demangle",self.bin]
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
        for x in lines:
            if len(x)<1:
                self.dprint(x)
                continue
            symadd=x[0:8]
            symtype=x[9:10]
            symname=x[11:len(x)]
            ltype=symbol_dict.get(symtype,None)
            if not ltype:
                symbol_dict[symtype]=list()
            x=symname.rstrip()
            if x in self.bad_syms:
                continue
            symbol_dict[symtype].append({'name':symname,'address':symadd,'type':symtype})
        return symbol_dict

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

    def obtain_fn_objdump(self,fn):
        if self.binutils_version<2.32:
            if not self.bin_objdump:
                self.bin_objdump = self.obtain_objdump()
            return self.get_func_disasm(self.bin_objdump,fn)
        else:
            disasm_fn="--disassemble={}".format(fn.rstrip().lstrip())
            objdump_cmd=["/usr/bin/objdump","-D","-C", disasm_fn,self.bin]
            egrep_cmd=["egrep","-v","'(Disassembly|file format|^$)'"]
            cmd=objdump_cmd+["|"]+egrep_cmd
            #print(cmd)
            out = subprocess.check_output(" ".join(cmd),shell=True)
            dump=out.decode("ascii").split('\n')
            #print(dump[0:5])
            return dump



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
        myINFO=elf_file(args.exe,args.sym_info,args.debug)
        if args.json:
            myINFO.dump_json(args.json)
        if not args.sym_info:
            import sys; sys.exit(0)
    if args.json_in:
        myINFO=elf_file()
        myINFO.load_json(args.json_in)
        # not sure what to do with this, but sure, okay
         
    x,x1,x2=(None,None,None)
    if args.min_inst:
        x1=myINFO.get_functions_min_instr(args.min_inst)
        x=x1
    if args.min_bytes:
        x2=myINFO.get_functions_min_bytes(args.min_bytes)
        if args.min_AND and x1:
            x=x1 & x2
        elif x1:
            x=x1 | x2
        else:
            x=x2
    if x:
        for i in x:
            print(i)
