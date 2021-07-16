#!/usr/bin/env python3.7
import subprocess,os,copy,re


class prd_cfg:
    
    def __init__(self,srcdir,prd_dir,prd_info,gp_exe,prophet_info,debug):
        self.srcdir=srcdir
        self.prd_info=prd_info
        self.load_cb_info()
        self.gp_exe=gp_exe
        self.funcinsert=f"{prd_dir}/funcinsert.py"
        self.prophet_base=prophet_info[0]
        self.prophet_exe=prophet_info[1]
        self.test_script=f"{self.srcdir}/test.sh"
        x=self.cb_info.get('NUM_POS',None)
        self.debug=debug[0]
        self.debug_log=debug[1]
        # temporary : always get and override test information in prd_info.json
        #if not x:
        if True:
            self.get_test_info()
            self.write_cb_info(self.prd_info)
    
    def dprint(self,*args, **kwargs):
        if self.debug:
            print(*args, **kwargs)
        if self.debug_log: 
            with open(self.debug_log,"a") as f:
                #print(*args,**kwargs,file=f,flush=True)
                print(*args,file=f,flush=True)

    def setup_basic_cb(self,srcdir,destdir):
        links=[ "poller", "tools", "Makefile.prd", "test.sh", "prd_info.json",
        "prd_include.mk", "defs.h", "script.ld", self.cb_info['BIN'], 
        "{}_recomp.c".format(self.cb_info['BIN']), "defs.h", "pov*.pov"]
        #cwd=os.getcwd()
        #os.chdir(destdir)
        added_files=[]
        for l in links:
            srch="{}/{}".format(srcdir,l)
            import glob
            files=glob.glob(srch)
            self.dprint(f"Looking for {srch}")
            for f in files:
                bf=os.path.basename(f)
                destbf=f"{destdir}/{bf}"
                lnk_src=os.path.realpath(f)
                if os.path.exists(destbf):
                    os.unlink(destbf)
                os.symlink(lnk_src,destbf)
                added_files.append(bf)
        #os.chdir(cwd)
        # now some errata - files with full paths
        for l in [self.funcinsert]:
            bf=os.path.basename(l)
            destbf=f"{destdir}/{bf}"
            lnk_src=os.path.realpath(l)
            if os.path.exists(destbf):
                os.unlink(destbf)
            os.symlink(lnk_src,destbf)
            added_files.append(bf)
        self.dprint(f"Added {added_files}")
        return added_files

        
    def reinitialize_bin_info(self):
        self.load_cb_info()
        self.get_test_info()
        self.write_cb_info(self.prd_info)

    def setup_basic(self,srcdir,destdir,scriptdir,gpdest,pdest):
        for i in [destdir,scriptdir,gpdest,pdest]:
            if not os.path.exists(i):
                try:
                    os.makedirs(i)
                except Exception as e:
                    print(f"Attempting to create directory '{i}'")
                    print(e)
                    raise
        self.setup_basic_cb(srcdir,destdir)



    def preprocess_for_genprog(self,name,srcdir):
        preprocess='perl -pi -e\'s/(enum|union) \$/$1 ${1}_/g\' '+f"{name}_recomp.c"
        cwd=os.getcwd()
        os.chdir(srcdir)
        perl_result=subprocess.check_output(preprocess,shell=True).decode('ascii')
        os.chdir(cwd)
        return perl_result
        
        
    def setup_genprog(self,name,srcdir,destdir,scriptdir):
        """ """
        src_success=self.preprocess_for_genprog(name,srcdir)
        povs=self.generate_pov_test_scripts(srcdir)
        cfgs=self.generate_genprog_cfgs(srcdir)
        
        for i,p in enumerate(povs):
            script=f"{scriptdir}/gp.{name}.{p}.bash"
            d=f"{destdir}/{name}.{p}"
            import shutil
            self.dprint(f"Copying {srcdir} into {d}")
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(srcdir,d,symlinks=True)
            run=self.generate_genprog_run(self.gp_exe,cfgs[i])
            srun=f"#!/bin/bash\n\npushd {d} > /dev/null\n{run}\npopd > /dev/null\n"
            with open(script,'w') as sf:
                sf.write(srun)
                sf.close
            os.chmod(script,0o755)
            

    def get_funcinsert_options(self):
        prefix=self.cb_info.get('DETOUR_PREFIX',"")
        x="--genprog "
        x+=" ".join(self.cb_info['DETOURS'])+" "
        fstubs=list([""]);
        fstubs+=list(self.cb_info['FUNCSTUB_LIST'].values())
        x+=" --external-funcs {}".format(prefix).join(fstubs)+" "
        return x
        
    def generate_genprog_run(self,genprog_exe,cfg):
        prefix="mkdir -p logs\nmake -f Makefile.prd hook\n"
        gp_="timeout -k 16h 16h {0} {1} ".format(genprog_exe,cfg)
        ext=[
        "--search brute |& tee logs/gp.brute_force.log", 
        "--search brute --subatom-mutp 1.0 --continue |& tee logs/gp.brute_force_subatom_all.log", 
        "--crossover subset --delp 0.33333 --fitness-in-parallel 2 --neg-weight 1 --pos-weight 0.1 --repp 0 --sample 1 --search ww --swapp 0.33333 |& tee logs/gp.ae_tool.log",
        " |& tee logs/gp.ga.log"
        ]
        gp_cmds=[gp_+x for x in ext]
        full_gp_cmd=prefix+"\n"+"\n".join(gp_cmds)
        return full_gp_cmd

    def generate_genprog_cfgs(self,outdir):
        detours=self.get_detour_entries()
        funcinsert_cmd="{} {}".format(self.funcinsert,self.get_funcinsert_options())
        no_instr=["--do-not-instrument "+x for x in detours ]
        gp_cfg="--seed 0\n--disable-aslr\n--program {0}_recomp.i\n--search ga\n--popsize 40\n"
        gp_cfg+="--generations 10\n--compiler gcc\n--func-repair\n--func-repair-binary ./{0}\n"
        gp_cfg+="--func-repair-insert {0}_recomp.c\n--minimization\n--edit-script\n"
        gp_cfg+="--trampoline-compiler-opts -m32 -fPIC -static-pie -shared -z now\n"
        gp_cfg+="--trampoline-linker-opts -Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,now,-z,norelro,-T,script.ld,-static \n"
        gp_cfg+="\n".join(no_instr)+"\n"
        gp_cfg+="--func-repair-script {}\n".format(funcinsert_cmd)
        gp_line=gp_cfg.format(self.cb_info['BIN'])+"--pos-tests {}\n".format(self.cb_info['NUM_POS'])
        #^^ shared Genprog configuration
        # distinct configurations
        full_gp=gp_line+"--neg-tests {}\n".format(self.cb_info['NUM_NEG'])
        gp_cfg="{}/cfg-{}".format(outdir,"default")
        with open(gp_cfg,'w') as f:
            f.write(full_gp)
            f.close()

        cfgs=[]
        for i in self.cb_info['POVS']:
            pov_gp=gp_line
            pov_gp+="--neg-tests 1\n"
            pov_gp+="--test-script ./test-{}.sh\n".format(i)
            cfg="cfg-{}".format(i)
            cfgs.append(cfg)
            gp_cfg="{}/{}".format(outdir,cfg)
            with open(gp_cfg,'w') as f:
                f.write(pov_gp)
                f.close()

        return cfgs
        

    def get_detour_entries(self):
        return [x.split(':',1)[0] for x in self.cb_info['DETOURS'] ]


    def generate_pov_test_scripts(self,outdir):
        start_neg="sed -n '/^n1)/{=; q;}' "+self.test_script
        lines2capture=int(subprocess.check_output(start_neg,shell=True).decode('ascii'))-1
        top_test="head -n {}  {}".format(lines2capture,self.test_script)
        captured=subprocess.check_output(top_test,shell=True).decode('ascii')
        povs=[] 
        for x in self.cb_info['NEG_TESTS']:
            pov=re.sub("^.*(pov_\d+).*$","\g<1>",x)
            self.dprint(f"{x} => {pov}")
            pov_test_script=captured+"\nn1)\n"+x+"\n;;\nesac\n\nexit $?"
            s="test-{}.sh".format(pov)
            fname="{}/{}".format(outdir,s)
            with open(fname,'w') as f:
                f.write(pov_test_script)
                f.close()
            os.chmod(fname,0o755)
            povs.append("{}".format(pov))
        return povs
        
    def get_test_info(self):
        cmd=["perl -p -e'if (/^[^#]*","{}","/){ print $_; } undef $_; ' ","{}"]
        pos_cmd=copy.copy(cmd); pos_cmd[1]="cb-replay.py"; pos_cmd[3]=self.test_script; poscmd="".join(pos_cmd)
        neg_cmd=copy.copy(cmd); neg_cmd[1]="cb-replay-pov.py"; neg_cmd[3]=self.test_script; negcmd="".join(neg_cmd)
        pos_testruns=subprocess.check_output(poscmd,shell=True).decode('ascii').rstrip().split('\n')
        self.cb_info['NUM_POS']=len(pos_testruns)
        neg_testruns=subprocess.check_output(negcmd,shell=True).decode('ascii').rstrip().split('\n')
        self.cb_info['NUM_NEG']=len(neg_testruns)
        povs=[ re.sub("^.*(pov_\d+)\.pov.*$","\g<1>",x)  for x in neg_testruns  ]
        self.cb_info['POVS']=povs
        self.cb_info['POS_TESTS']=pos_testruns
        self.cb_info['NEG_TESTS']=neg_testruns
        

    def write_cb_info(self,out):
        import json
        with open(out,'w') as outFile:
            json.dump(self.cb_info,outFile)

    def load_cb_info(self):
        import json
        with open(self.prd_info,'r') as inFile:
            self.cb_info = json.load(inFile)

    def get_revlog_info(self):
        num_neg=self.cb_info['NUM_NEG']
        num_pos=self.cb_info['NUM_POS']
        rlog_all=f"-\n-\nDiff Cases: Tot {num_neg}\n"
        rlog_all+=" ".join([str(i) for i in range(0,num_neg)])+"\n"
        rlog_pos=f"Positive Cases: Tot {num_pos}\n"
        rlog_pos+=" ".join([str(i) for i in range(num_neg,num_neg+num_pos)])+"\n"
        rlog_all+=rlog_pos
        rlogs=dict()
        for i,neg in enumerate(self.cb_info['NEG_TESTS']):
            pov=re.sub("^.*(pov_\d+).*$","\g<1>",neg)
            rlogs[pov]=f"-\n-\nDiff Cases: Tot 1\n{i}\n"+rlog_pos
        rlogs['all']=rlog_all

        return rlogs

    def get_conf_info(self,name,rlogs:dict,revdir,srcdir,ptooldir):
        conf_rev=dict()
        prd_src=f"{name}_recomp.c"
        for ext,val in rlogs.items():
            # now let's get the prophet .conf info
            cf=f"{revdir}/{name}.{ext}.revlog"
            cfg=f"revision_file={cf}\nsrc_dir={srcdir}\ntest_dir={srcdir}\n"
            cfg+=f"build_cmd={ptooldir}/cgc-prd-build.py\n"
            cfg+=f"test_cmd={ptooldir}/cgc-prd-test.py\n"
            cfg+=f"localizer=profile\nbugged_file={prd_src}\n"
            cfg+=f"fixed_out_file=prd_{name}_{ext}_\n"
            cfg+=f"single_case_timeout=12\nwrap_ld=no\nchallenge={name}\nmakefile=Makefile.prophet\n"
            cfg+="makefile_target=all\n"
            # and populate the dict
            conf_rev[ext]=dict()
            conf_rev[ext]['rev']=val
            conf_rev[ext]['cfg']=cfg
        return conf_rev

        
    def setup_prophet(self,name,srcdir,destdir,scriptdir,ptooldir,prophet_base):
        """ this is pretty much what's in the revlog_prophet-prd.bash script """
        pbindir=f"{destdir}/src"
        prundir=f"{destdir}/runs"
        revdir=f"{destdir}/revlog"
        logdir=f"{destdir}/logs"
        bindest=f"{pbindir}/{name}"
        cfgdir=f"{destdir}/cfg/{name}"
        for i in [pbindir,prundir,cfgdir,revdir,logdir]:
            if not os.path.exists(i):
                os.makedirs(i)
        import shutil
        if os.path.exists(f"{bindest}"):
            shutil.rmtree(bindest)
        shutil.copytree(srcdir,bindest,symlinks=True)
        os.unlink(f"{bindest}/{name}_recomp.c")
        shutil.copyfile(f"{srcdir}/{name}_recomp.c",f"{bindest}/{name}_recomp.c",follow_symlinks=True)
        self.dprint("Copying "+f"{srcdir}/{name}_recomp.c"+" to "+f"{bindest}/{name}_recomp.c")
        #have to get rid of the checking in the original makefile that gets included
        smake=f"{srcdir}/Makefile.prd"
        dmake=f"{bindest}/Makefile.prd"
        os.unlink(f"{bindest}/Makefile.prd")
        # let's 
        mkprt=f"cat {smake} | egrep -vw '(check)' > {dmake}"
        subprocess.check_output(mkprt,shell=True)
        
        # setting up specific files for Prophet prd-specific scripts (cgc-prd-build.py, cgc-prd-test.py)
        # need: Makefile.prophet, configuration-func-repair 
        smake=f"{ptooldir}/Makefile.prd_prophet"
        dmake=f"{bindest}/Makefile.prophet"
        shutil.copyfile(smake,dmake,follow_symlinks=False)
        with open(f"{bindest}/configuration-func-repair","w") as fh:
            fh.write(f"--neg-test {self.cb_info['NUM_NEG']}\n")
            fh.write(f"--pos-test {self.cb_info['NUM_POS']}\n")
            fh.close()
        # done

        # creating revlog and conf files - directs Prophet how to run
        rlogs=self.get_revlog_info()
        rcfgs=self.get_conf_info(name,rlogs,os.path.realpath(revdir),os.path.realpath(bindest),ptooldir)
        frun=os.path.realpath(prundir)
        lrun=os.path.realpath(logdir)
        prophet_script=f"#!/bin/bash\n\nexport PROPHET64_BASE={prophet_base}\n"
        prophet_script+=f"echo \"[PROPHET][START] {name}\"\n"
        prophet_script+=f"mkdir -p {frun}/{name} ;\npushd {frun}/{name}\n"

        for ext,val in rcfgs.items():
            if ext=="all":
                # let's skip the ALL POV configuration
                continue
            rev=val['rev']
            revlog_f=f"{revdir}/{name}.{ext}.revlog"
            with open(revlog_f,'w') as f:
                f.write(rev)
                f.close()

            conf=val['cfg']
            conf_f=f"{cfgdir}/{name}.{ext}.conf"
            with open(conf_f,'w') as f:
                f.write(conf)
                f.close()
            pconf=os.path.realpath(conf_f)
            log=f"{lrun}/{name}.{ext}.log"
            prophet_script+=f"echo \"[PROPHET][START] {name}.{ext}\"\n"
            prophet_script+=f"{prophet_base}/src/prophet {pconf} -r {name}.{ext} -vl=10 -ll=10 >& {log}\n"
            prophet_script+=f"echo \"[PROPHET][DONE] {name}.{ext}\"\n\n"

        prophet_script+=f"popd\necho \"[PROPHET][DONE] {name}\"\n"

        pscript=f"{scriptdir}/prophet.{name}.bash"
        with open(pscript,"w") as f:
            f.write(prophet_script)
            f.close()
        os.chmod(pscript,0o755)

        return pscript

def parse_arguments():
    
    import sys,argparse
    env=os.environ
    prd_base_dir=env.get('PRD_BASE_DIR',None)
    base_dir=env.get('CGC_CB_DIR',None)
    prophet_prd_dir=f"{prd_base_dir}/tools/apr/prophet" if prd_base_dir else None
    gpsrc_dir=env.get('PRD_GENPROGSRC_DIR',None)
    llvm_clang_gcc_dir=env.get('LLVM_CLANG_GCC',None)
    prophet_base=env.get('PROPHET64_BASE',None)
    pr_req=(prophet_base==None)
    gp_req=True if not gpsrc_dir else False
    parser = argparse.ArgumentParser(description=\
             "Generate APR infrastructures for a PRD binary [GenProg, Prophet]")
    parser.add_argument("--base-tool-dir",dest="toolbasedir",type=str,default=base_dir,
        help="specify base directory that contains tools and prophet subdirectories [default: $CGC_CB_DIR]")
    parser.add_argument("--genprog-dest-dir",dest="gpdest",type=str, required='--dest-dir' not in sys.argv,
        help="specify destination directory for GenProg APR run [overrides default from --dest-dir] ")
    parser.add_argument("--prophet-dest-dir",dest="pdest",type=str, required='--dest-dir' not in sys.argv,
        help="specify destination directory for Prophet APR run [overrides default from --dest-dir] ")
    parser.add_argument("--dest-dir",dest="destdir",type=str, default=None, 
        required='--genprog-dest-dir' not in sys.argv or '--prophet-dest-dir' not in sys.argv,
        help="specify destination directory for APR run - not required if both --prophet-dest-dir and --genprog-dest-dir are supplied ")
    parser.add_argument("--src-dir",dest="srcdir",type=str, required=True, 
        help="specify srcdir of PRD binary, must contain 'prd_info.json' if --prd-info is not specified")
    parser.add_argument("--bin-test-script",dest="bintest",type=str, 
        help="specify test script [default : srcdir/test.sh]")
    parser.add_argument("--genprog-exe",dest="genprog",type=str, default="{}/repair".format(gpsrc_dir), 
        required=gp_req,
        help="specify GenProg executable [default : $PRD_GENPROGSRC_DIR/repair]")
    parser.add_argument("--prophet-exe",dest="prophet",type=str, default="{}/src/prophet".format(gpsrc_dir), 
        required=pr_req,
        help="specify GenProg executable [default : $PRD_GENPROGSRC_DIR/repair]")
    parser.add_argument("--prd-info",dest="prdinfo",type=str, default=None,
        help="specify 'prd_info.json' filepath [default : srcdir/prd_info.json]")
    parser.add_argument("--debug",dest="debug",action="store_const",const=True,default=False,
        help="Output debug information")
    parser.add_argument("--debug-log",dest="debuglog",type=str,default=None,
        help="Output debug information")
    
    args=parser.parse_args()
    if not args.prdinfo:
        args.prdinfo="{}/prd_info.json".format(args.srcdir)
    if not args.pdest:
        args.pdest="{}/prophet_".format(args.destdir)
    if not args.gpdest:
        args.gpdest="{}/genprog_".format(args.destdir)
    if not prophet_base and args.prophet:
        prophet_base=args.prophet.split("/src/prophet",1)[0]
    else:
        print(f"PROBLEM [{pr_req}] - prophet-related information not provided")
        

    args.prophet_dir=prophet_base
    args.prophet_prd_dir=prophet_prd_dir
    args.prd_dir=prd_base_dir
        

    return args



def main():
    args=parse_arguments()
    proph=[args.prophet_dir,args.prophet]
    debug_info=[args.debug,args.debuglog]
    binPRD=prd_cfg(args.srcdir,args.prd_dir,args.prdinfo,args.genprog,prophet_info=proph,debug=debug_info)

    name=binPRD.cb_info['BIN']
    scriptdir= scriptdir=f"{args.destdir}/scripts" if args.destdir else os.path.realpath(os.getcwd())+"/scripts"
    destdir=f"{args.destdir}/prd_src/{name}" if args.destdir else os.path.realpath(os.getcwd())+f"/prd_src/{name}"
    
    binPRD.setup_basic(srcdir=args.srcdir,destdir=destdir,scriptdir=scriptdir,
        gpdest=args.gpdest,pdest=args.pdest)#ptooldir=args.prophet_prd_dir)
    binPRD.setup_prophet(name=name,srcdir=destdir,destdir=args.pdest,scriptdir=scriptdir,
        ptooldir=args.prophet_prd_dir, prophet_base=args.prophet_dir)
    binPRD.setup_genprog(name,destdir,args.gpdest,scriptdir=scriptdir)
    



if __name__ == "__main__":
    main()
