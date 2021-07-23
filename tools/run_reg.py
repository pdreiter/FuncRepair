#!/usr/bin/env python3
import os

class run_reg:

    def __init__(self,cb,ids,bindir,outdir,pkldir,dbi,timeout):
        self.cb=cb
        self.ids=ids
        self.bin_dir=bindir
        self.out_dir=outdir
        self.dbi=dbi
        self.timeout=timeout
        self.tests=dict()
        print(f"Getting test content from {pkldir}")
        self.tests=self.get_test_content(pkldir,self.cb)
    

    def get_test_content(self,pkldir,cb):
        import glob
        tests=dict()
        pdir=pkldir
        pkls=glob.glob(f"{pkldir}/*.pkl")
        if os.path.exists(f"{pdir}/{cb}") and len(pkls)==0:
            pkls=glob.glob(f"{pkldir}/{cb}/*.pkl")
        for i in pkls:
            import pickle
            with open(i,'rb') as fi:
                x=pickle.load(fi)
                t={'expected':x['expected'],'write':x['write'],'seed':x['seed']}
                tests[x['id']]=t
        return tests

    def run(self):
        my_env={}
        ret=list()
        print(f"Running:")
        for i in range(0,len(self.ids)):
            exe=self.ids[i]
            exe_id=os.path.basename(self.ids[i])
            fullp_exe=os.path.realpath(exe)
            if not os.path.exists(fullp_exe) and os.path.exists(f"{self.bin_dir}/{exe}"):
                fullp_exe=f"{self.bin_dir}/{exe}"
            if not os.path.exists(fullp_exe):
                print(f"Skipping: {os.path.basename(fullp_exe)} does not exist!")
                continue
            prefix=f"{self.out_dir}/{exe_id}"
            if not os.path.exists(prefix):
                os.makedirs(prefix)
            for ID,test in self.tests.items():
                id_=os.path.basename(ID)
                # stdout/stderr log
                my_env['seed']=test['seed']
                my_env['LD_BIND_NOW']=str(1)
                cmd=f"{self.dbi}" if self.dbi else ""
                cmd+=f" {fullp_exe}"
                import re
                cmd=re.sub('{ID}',str(id_),cmd)
                cmd=re.sub('{CB}',str(self.cb),cmd)
                cmd=re.sub('{OUT}',f"{prefix}",cmd)
                print(f"- [seed={test['seed']}] {cmd}",flush=True)
                import shlex,subprocess
                args=shlex.split(cmd)
                # this doesn't generate more than just a header in perf.log
                #p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=my_env)
                #byt=bytes(test['write'])
                ##print(f"{type(byt)} : {byt}",end='')
                #try:
                #    sout,serr=p.communicate(byt,timeout=int(self.timeout))
                #except TimeoutExpired as e:
                #    print(f"Timeout for {exe_id}")
                #    p.kill()
                #    sout,serr=p.communicate()

                #for byt in sout.decode('ascii'):
                #    print(f"{byt}",end='')

                byt=bytes(test['write'])
                #print(f"{type(byt)} : {byt}",flush=True)
                capt=True
                try:
                    sout=subprocess.run(args,input=byt,env=my_env,\
                    capture_output=capt,\
                    timeout=float(self.timeout)\
                    )
                except Exception as e:
                    raise(e)

                if capt:
                    log=f"{prefix}/run.{id_}.log"
                    with open(log,"w") as r:
                        r.write(sout.stderr.decode("ascii"))
                        r.write(sout.stdout.decode("ascii"))
                        r.close()
                ret.append(sout.returncode)
        return ret
        

def main():
    import os,argparse
    perf_dbi="/usr/bin/perf stat -o {OUT}/{ID}.perf.log "
    default_dir=os.getcwd()
    parser = argparse.ArgumentParser(description='Run regression')
    required = parser.add_argument_group(title='required arguments')
    required.add_argument('--cb',required=True,
                          help='Binary to run, name used to correlate test run data')
    parser.add_argument('--debug',required=False,action='store_true')
    # executable names to run
    parser.add_argument('--exec-ids',dest='ids',nargs='*',required=False,default=None,
                        help="Executables to run with binary content"
    )
    parser.add_argument('--bin-dir',dest='bindir',required=False,default=default_dir)
    parser.add_argument('--results-dir',dest='resdir',required=False,default=default_dir)
    parser.add_argument('--pkl-dir',dest='pkldir',required=False,default=None)
    parser.add_argument('--dbi',dest='dbi',required=False,default=None)
    parser.add_argument('--perf',dest='perf',required=False,default=False,action='store_true')
    parser.add_argument('--timeout',dest='timeout',required=False,default=5)

    args = parser.parse_args()
    if not args.pkldir:
        args.pkldir=f"{args.bindir}/pkl"
    if args.perf:
        args.dbi=perf_dbi
    
    reg=run_reg(args.cb,args.ids,args.bindir,args.resdir,args.pkldir,args.dbi,args.timeout)
    reg.run()
        





if __name__ == "__main__":
    main()
