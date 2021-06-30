#!/usr/bin/env python3

class run_reg:

    def __init__(self,cbs,ids,rundir,pkldir,dbi,timeout):
        self.cbs=cbs
        self.ids=ids
        self.run_dir=rundir
        self.dbi=dbi
        self.timeout=timeout
        self.tests=self.get_test_content(pkldir)
    

    def get_test_content(self,pkldir):
        import glob
        tests=dict()
        pkls=glob.glob(f"{pkldir}/*.pkl")
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
        for i in range(0,len(self.cbs)):
            exe=self.cbs[i]
            exe_id=self.ids[i] if (self.ids and (i<=len(self.ids))) else exe
            for ID,test in self.tests.items():
                my_env['seed']=test['seed']
                my_env['LD_BIND_NOW']=str(1)
                cmd=f"{self.dbi} {exe}" if self.dbi else f"{exe}"
                import re
                cmd=re.sub('{ID}',str(ID),cmd)
                cmd=re.sub('{CB}',str(exe_id),cmd)
                print(f"- {cmd}")
                import shlex,subprocess
                args=shlex.split(cmd)
                p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=my_env)
                try:
                    sout,serr=p.communicate(test['write'],timeout=self.timeout)
                except TimeoutExpired:
                    print(f"Timeout for {exe_id}")
                    p.kill()
                    sout,serr=p.communicate()
                ret.append(p.returncode)
        return ret
        

def main():
    import os,argparse
    default_dir=os.getcwd()
    parser = argparse.ArgumentParser(description='Run regression')
    required = parser.add_argument_group(title='required arguments')
    required.add_argument('--cbs',nargs='+',required=True,
                          help='List of binaries to run')
    parser.add_argument('--debug',required=False,action='store_true')
    parser.add_argument('--ids',dest='ids',nargs='*',required=False,default=None)
    parser.add_argument('--run-dir',dest='rundir',required=False,default=default_dir)
    parser.add_argument('--pkl-dir',dest='pkldir',required=False,default=None)
    parser.add_argument('--dbi',dest='dbi',required=False,default=None)
    parser.add_argument('--timeout',dest='timeout',required=False,default=5)

    args = parser.parse_args()
    if not args.pkldir:
        args.pkldir=f"{args.rundir}/pkl"
    
    reg=run_reg(args.cbs,args.ids,args.rundir,args.pkldir,args.dbi,args.timeout)
    reg.run()
        





if __name__ == "__main__":
    main()
