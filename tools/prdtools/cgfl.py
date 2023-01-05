#!/usr/bin/env python3
import sys,os,re,glob,copy
from prdtools import elf

script_dir=os.path.dirname(os.path.abspath(__file__))

class cgfl:
    def __init__(self,cb=None,src=None,inputdir=None,outputdir=None,valid_funcs=None,debug=False):
        self.cb=cb
        self.srcdir=src
        self.cg_in_dir=inputdir
        self.cg_out_dir=outputdir
        self.debug=debug
        x="{}/tmp".format(self.cg_out_dir)
        if not os.path.exists(x):
             os.makedirs(x)
        self.cg_annotate="callgrind_annotate --include={} --threshold=100 {}/{}.cg.out"
        self.raw_data=dict()
        self.screened_data=dict()
        # list of tuples of (demangled function name, mangled name)
        self.valid_funcs=list(valid_funcs)
        self.demangled_funcs=self.get_demangled(valid_funcs)
        #for i in valid_funcs:
        #    print(f" - '{i}'")
        self.test_files=None
        if self.cg_out_dir:
            test_files=glob.glob("{}/*.cg.out".format(self.cg_out_dir))
            for t in test_files:
                s="\/([pn]\d+)\.cg\.out".format(self.cg_out_dir)
                t_re=re.compile(s)
                t__ = t_re.search(t)
                if t__:
                    test=t__.group(1)
                    if not self.test_files:
                        self.test_files=dict()
                    self.test_files[test]=t
            if not self.test_files or len(self.test_files)==0:
                print("ERROR: No valid CGFL data from {} test runs!!".format(self.cb),file=sys.stderr)
                print(f"test_files : {test_files}",file=sys.stderr)
                print(f"Check out : {self.cg_out_dir}/*.cg.out",file=sys.stderr)

    def annotate(self):
        if not self.test_files or len(self.test_files)==0:
            print("ERROR: No valid CGFL data from {} test runs!!".format(self.cb),file=sys.stderr)
            sys.exit(-1)
        for test,cg_out in self.test_files.items():
            self.run_cg_annotate(test,cg_out)

    def get_demangled(self,l):
        if len(self.valid_funcs)<=0:
            return []
        else:
            return [ x if '(' not in x else x.split('(',1)[0] \
                                for x in [v[0] for v in self.valid_funcs] \
                             ]

    def set_valid_funcs(self,valid_list):
        self.valid_funcs=valid_list
        self.demangled_funcs=self.get_demangled(valid_list)

    def run_cg_annotate(self,test,test_cgout):
        import shlex, subprocess
        cmd=shlex.split(self.cg_annotate.format(self.srcdir,self.cg_out_dir,test))
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        sout,serr=proc.communicate()
        output=sout.decode('utf-8')
        if self.debug:
            print("[DEBUG] Running callgrind_annotate => {}".format(" ".join(cmd)))
            print("[DEBUG] output => {}".format(output))
            print("[DEBUG] stderr => {}".format(serr.decode('utf-8')))
        outf="{}/{}/{}.annot".format(self.cg_out_dir,"tmp",test)
        with open(outf,'w') as f:
            f.write(output)
            f.close()
        lines=output.split('\n')
        #(echo "{"; perl -p -e'if (/^\s*((\d+,)*\d+)\s+\S+:([^\s\(]+)(\s+|\()/){ my ($func,$val)=($3,$1); $val=~s/,//g; print "\"$func\":$val,\n";} undef $_;' $log_dir/tmp/$TEST.annot; echo "}") > $log_dir/tmp/$TEST.dict; 

        func_re=re.compile("^\s*((\d+,)*\d+)\s+\S+(?<!:):(?!:)([^\s\(]+)(\s+|\()")
        rawhash=dict()
        filteredhash=dict()
        for x in lines:
            fn=func_re.search(x)
            if not fn:
                pass
            elif fn:
                val=int(re.sub(',','',fn.group(1)))
                func=fn.group(3)
                rawhash[func]=val
                # let's check the callgrind output based on demangled name
                if self.demangled_funcs and func in self.demangled_funcs:
                    filteredhash[func]=val

        self.raw_data[test]=rawhash
        self.screened_data[test]=filteredhash

    def write_raw_dicts(self):
        for test in self.test_files.keys():
            data=self.raw_data.get(test,None)
            if data:
                outf=self.get_outf(test,True)
                self.write_dict(data,outf)

    def write_screened_dicts(self):
        self.create_all_dict()
        for test in self.test_files.keys():
            data=self.screened_data.get(test,None)
            if data:
                outf=self.get_outf(test)
                self.write_dict(data,outf)
        all_f=self.get_outf("all")
        self.write_dict(self.all_dict,all_f)
            
                
    def get_outf(self,test,tmp=False):
        subdir=""
        if tmp:
            subdir="tmp/"
        dict_outf="{}/{}{}.dict".format(self.cg_out_dir,subdir,test)
        return dict_outf

    def write_dict(self,data,datafile):
        with open(datafile,'w') as f:
            import json
            json.dump(data,f)
            f.close()

    def screen_dicts(self,exclude):
        screen_="({})".format(exclude)
        screen_re=re.compile(r"\b"+screen_+r"\b")
        orig_s=copy.deepcopy(self.screened_data)
        screened=list()
        for y in orig_s.keys():
            for x in orig_s[y].keys():
                screenme=screen_re.search(x)
                if screenme:
                    screened.append(screenme.group(1))
                    del self.screened_data[y][x]
        return screened

    def keep_dicts(self,keep):
        keep_="({})".format(keep)
        keep_re=re.compile(keep_)
        for y in self.raw_data.keys():
            for x in self.raw_data[y].keys():
                yy=self.screened_data.get(y,None)
                if not yy:
                    self.screened_data[y]=dict()
                keepme=keep_re.search(x)
                if keepme:
                    self.screened_datay[y][x]=self.raw_data[y][x]
                else:
                    yy=self.screened_data[y].get(x,None)
                    if yy:
                        del self.screened_data[y][x]

    def create_all_dict(self):
        self.all_dict=dict()
        for f in self.screened_data.keys():
            self.all_dict.update(self.screened_data[f])

        for f in self.all_dict.keys():
            self.all_dict[f]=0


def get_satisfying_symbols(binelf,exclude_me_:str,mininst:int=None,minbytes:int=1,minAND:bool=False,
    debug:bool=False):
    satisfied=None
    minset=elf.get_min_set(binelf,min_inst=mininst,min_bytes=minbytes,min_AND=minAND)
    exclude_re=re.compile(r'\b('+exclude_me_+r')\b')
    _functions=minset
    if not _functions or len(_functions)<1:
        print("ERROR!  We have no min set of functions! Why?")
        print(f"Functions => {_functions}")
        sys.exit(-1)
    elif debug:
        for sym,demangled in _functions:
            print(f"symbol:{sym}  => demangled:{demangled}")
        
    output="Satisfying symbols:"
    for sym,demangled in _functions:
        y=exclude_re.search(demangled)
        if not y:
            if not satisfied:
                satisfied=list()
            xf=demangled.split("(",1)[0]
            xf=re.sub("^\s*const\s*","",xf)
            satisfied.append((xf,sym))
            output+=f"- {sym}"+"\n"
    return satisfied

            



# initialize symbols we'd like to screen by default
init_re='__frame_dummy_init_array_entry|_init|__init_array_end|__init_array_start|__libc_csu_init|mutex_init'
fini_re='__do_global_dtors_aux_fini_array_entry|_fini|__libc_csu_fini'
thunk_re='__x86.get_pc_thunk.[abcds][ix]|__cxa_pure_virtual'
reg_re='deregister_tm_clones|register_tm_clones'
glob_re='__do_global_dtors_aux|__do_global_dtors_aux_fini_array_entry|_dl_relocate_static_pie'
start_re='_start|__init_array_start|start'
alloc_re='((cgc_)?(allocate_buffer|allocate_new_blk|allocate_span|filter_alloc|large_alloc|malloc_free|malloc_huge|run_alloc|small_alloc|small_alloc_run|tiny_alloc))'
L_re='\.L\d+'
globals_re='((cgc__?|c_?)?(v_sprintf_s|__moddi3|__divdi3|str_to_ulong|free|malloc|calloc|realloc|free|malloc_huge|allocate_new_blk|small_free|free_huge|memcpy|memset|memcmp|memchr|sprintf|snprintf|vsnprintf|vsprintf|vsfprintf|vprintf|vfprintf|fdprintf|printf|fflush|large_alloc|large_free|tiny_alloc|small_alloc|small_free|small_unlink_free|malloc_alloc|chunk_to_ptr|malloc_free|fread|ssmalloc|freaduntil|recvline|putc|recv|write|fwrite|memmove|coalesce|strcmp|strncmp|strchr|strnchr|strncat|strcat|bzero|itoa|atoi|atof|ftoa|strn?cpy|getc|strtol|strn?len|strsep|exit|is(alnum|alpha|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|xdigit)|to(ascii|lower|upper)|randint))'
specific_issue_re='((cgc__?)(gb_new|gb_reset))'

syms2exclude_=[globals_re,init_re,fini_re,thunk_re,reg_re,
                     glob_re,start_re,alloc_re,L_re,specific_issue_re]
exclude_="|".join(syms2exclude_)

if __name__ == "__main__":
    import argparse
    from datetime import datetime
    dateinfo=datetime.now().strftime("%d%m%Y%I%M%S")
    
    scriptdir=os.path.dirname(os.path.realpath(sys.argv[0]))
    default_cwd=os.path.realpath(".")
    default_src=default_cwd
    debug=False
    default_log=None


 
    def get_args():
        #def __init__(self,cb=None,src=None,inputdir=None,outputdir=None):
        parser=argparse.ArgumentParser(description=\
            "extract information from cgfl")
        parser.add_argument('--r-seed',dest='r_seed',action='store',default=None, 
            help='seed for Rscript')
        parser.add_argument('--top-k-percent',dest='top_k',action='store',default=None, 
            help='Percentage for Top-k results')
        parser.add_argument('--r-out',dest='r_out',action='store',default=None, 
            help='directory for R scripts')
        parser.add_argument('--profile',dest='profile',action='store',default=None, 
            help='directory for CGFL profile output')
        parser.add_argument('--results',dest='results',action='store',default=None, 
            help='directory for CGFL results')
        parser.add_argument('--src',dest='src',action='store',default=None, 
            help='SRC directory for callgrind annotation information')
        parser.add_argument('--cgfl-in',dest='cgfl_in',action='store',default=None, 
            help='CGFL Input directory to get annotation information')
        #parser.add_argument('--json-in',dest='json_in',action='store',default=None, 
        #    help='json input file to get ELF information')
        parser.add_argument('--instr-min',dest='min_inst',action='store',default=None, 
            help='minimum number of instructions a function requires to be outputted')
        parser.add_argument('--byte-min',dest='min_bytes',action='store',default=50, 
            help='minimum number of bytes a function requires to be outputted')
        #parser.add_argument('--no-sym-info',dest='sym_info',action='store_false',default=True,
        #    help="Obtain symbols but do not extract symbol information (no objdump)")
        parser.add_argument('--reduce',dest='reduce',action='store_true',default=False, 
            help="indicates to calc_susp_pp.py to remove any function that is never touched by positive or negative tests --- ONLY USED when RAFL input size is too large!")
        parser.add_argument('--AND-min',dest='min_AND',action='store_true',default=False,
            help='Need to satisfy both minimum number of bytes and instructions for a function to be outputted')
        parser.add_argument('--json-out',dest='json',action='store',default=None, 
            help='json output file to store ELF EXE information')
        parser.add_argument('--lib',dest='lib',action='store',default=None,
            help='lib file to objdump')
        parser.add_argument('--exe',dest='exe',action='store',default=None,
            help='exe file to objdump')
        parser.add_argument('--debug',dest='debug',action='store_const',const=True,default=False)
        args=parser.parse_args()
        return args
     
    
    args=get_args();
    import os
    cb=os.path.basename(args.exe)
    get_syms_cmd="{} --exe {} --json-out {} {}"
    satisfied=None
    from prdtools import elf
    exclude_me=exclude_
    if args.lib:
        import subprocess,shlex
        libelf=elf.elf_file(binary_path=args.lib,symbol_info=False,debug=False)
        libelf.dump_json("lib.json")
        lsyms=libelf.local_symbols
        mangled=[x[0] for x in lsyms]
        demangled=[x[1] for x in lsyms]
        _libfunctions=mangled
        #print("[DEBUG] output => {}".format(output))
        screen_me='|'.join(_libfunctions)
        #print("[DEBUG] screen_me => {}".format(screen_me))
        if len(screen_me)>1:
            exclude_me="{}|{}".format(exclude_me,screen_me)

    print("Excluding these functions: ({})".format(exclude_me))
    exclude_re=re.compile(r'\b('+exclude_me+r')\b')
    if args.exe:
        import subprocess,shlex
        binelf=elf.elf_file(binary_path=args.exe,symbol_info=True,debug=False)
        if args.debug:
            mangled=binelf.mangled()
            #print(f"[DEBUG] Mangled symbols:")
            #for i,m in enumerate(mangled):
            #    print(f"[DEBUG] {i}: {m}");
        print(f"Minimum bytes: {args.min_bytes}")
        minset=elf.get_min_set(binelf,min_inst=args.min_inst,min_bytes=args.min_bytes,min_AND=args.min_AND)
        #and_min="" if not args.min_AND else "--AND-min"
        #if args.min_inst:
        #    and_min+=f" --instr-min {args.min_inst} "
        #syms_exe=get_syms_cmd.format("{}/screen_small_functions.py".format(scriptdir),
        #                         args.exe, args.json, 
        #                         " --byte-min {} {}".format(args.min_bytes,and_min)
        #                            )
        #print("[ RUNNING ] Obtaining executable symbols [needed]:")
        #print(syms_exe)
        #cmd=shlex.split(syms_exe)
        #proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        #sout,serr=proc.communicate()
        #output=sout.decode('utf-8')
        #_functions=output.split('\n')
        _functions=minset
        if not _functions or len(_functions)<1:
            print("ERROR!  We have no min set of functions! Why?")
            import sys; sys.exit(-1)
        elif args.debug:
            for sym,demangled in _functions:
                print(f"symbol:{sym}  => demangled:{demangled}")
            
        output="Satisfying symbols:"
        for sym,demangled in _functions:
            y=exclude_re.search(demangled)
            if not y:
                if not satisfied:
                    satisfied=list()
                xf=demangled.split("(",1)[0]
                xf=re.sub("^\s*const\s*","",xf)
                satisfied.append((xf,sym))
                output+=f"- {sym}"+"\n"
        #output=serr.decode('utf-8')
        import sys
        print(output,file=sys.stderr)

    if not satisfied or len(satisfied)<1:
        print("ERROR!  We have no valid set of functions! Why?")
        sys.exit(-1)
    if args.debug:
        ssat=",\n".join([f"{s[0]} [s{1}]" for s in satisfied])
        print(f"These functions satisfy: {ssat}")
    print(f"# satisfying functions: {len(satisfied)}")
    cgfl_o = cgfl(cb=cb,src=args.src,inputdir=args.results,outputdir=args.results,valid_funcs=satisfied,debug=args.debug)
    cgfl_o.annotate()
    screened_out=cgfl_o.screen_dicts(exclude_me)
    print(f"Screened out these functions {','.join(screened_out)}")
    cgfl_o.write_raw_dicts()
    cgfl_o.write_screened_dicts()

    #$script_dir/prdtools/calc_susp_pp.py --ext ".dict" --in "$log_dir" --out $outdir --all_rank --pickle --standardize --print --r_input --r-out $r_dir --cb $EXE --top-k-percent $TOP_K  > $log_dir/$EXE.calc_susp_pp.log 2> $log_dir/$EXE.rscript.log
    if args.results and args.r_out and args.top_k:
        exe_dir=os.path.dirname(args.exe)
        calc_exe="{} --ext '.dict' --in {} --out {} --all_rank --pickle --standardize --print --r_input --r-out {} --cb {} --top-k-percent {} --debug {} --log {} {}".format(
        "{}/calc_susp_pp.py".format(scriptdir),
        args.results,
        exe_dir,
        args.r_out,
        cb,
        args.top_k,
        f" --r-seed {args.r_seed} " if args.r_seed else "",
        "{}/susp-fn.log".format(exe_dir),
        "--reduce" if args.reduce else ""
        )
        print("[ RUNNING ] Generating R scripts from input:")
        print(calc_exe)
        cmd=shlex.split(calc_exe)
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        sout,serr=proc.communicate()
        output=sout.decode('utf-8')
        print(output)
        s_out="{}/{}.calc_susp_pp.log".format(args.results,cb)
        with open(s_out,'w') as f:
            f.write(output)
            f.close()
        output=serr.decode('utf-8')
        s_err="{}/{}.rscript.log".format(args.results,cb)
        with open(s_err,'w') as f:
            f.write(output)
            f.close()


  
