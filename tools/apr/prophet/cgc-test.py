#!/usr/bin/env python2
#
# this file is based on and extended from the build and test scripts 
# provided by Prophet, but specific to CGC CB
#
from sys import argv, exit
import getopt
from os import chdir, getcwd, system, path, environ, unlink, symlink
import subprocess
#env_files=["IS_NEG","NEG_ARG","TMP_FILE"]; 

if __name__ == "__main__":
    opts, args = getopt.getopt(argv[1 :], "e:p:");
    profile_dir = "";
    challenge_name="";
    for o, a in opts:
        if o == "-e":
            challenge_name = a;
        if o == "-p":
            profile_dir = a;

    src_dir = args[0];
    test_dir = args[1];
    work_dir = args[2];
    #cname=challenge_name+".trampoline.bin"
    # in cgc-build, I'm copying the challenge into the out_dir
    cname=challenge_name
    testscript=test_dir+"/test.sh"
    if (len(args) > 3):
        ids = args[3 :];
        cur_dir = src_dir;
        if (profile_dir != ""):
            cur_dir = profile_dir;
        chal=cur_dir+"/"+cname;
        if (not path.exists(chal)):
           print "ERROR: PRD binary does not exist at "+chal 

        for i in ["tools", "poller"]:
            if not path.exists(cur_dir+"/"+i):
                try:
                    symlink(test_dir+"/"+i,cur_dir+"/"+i)
                except Exception as e:
                    print "Failed trying to link "+i
                    print "symlink source:  "+test_dir+"/"+i
                    print "symlink dest:  "+cur_dir+"/"+i
                    print e


        #if (not path.exists(cur_dir + "/r")):
        #    system("mv " + cur_dir + "/poller" + cur_dir + "/fbc-src/oldtests");
        #    system("cp -rf " + test_dir + " " + cur_dir + "/fbc-src/tests");

        #super hacky, because fbc itself calls *ld*, damn it fbc
        fullpath = path.abspath(path.dirname(argv[0]));
        #wrappath = fullpath + "/../build/wrap";
        wrappath = fullpath + "/wrap";
        #system("rm -rf " + wrappath + "/gcc");
        #system("rm -rf " + wrappath + "/cc");

        ori_dir = getcwd();
        #chdir(cur_dir + "/fbc-src/tests");
        #print "Changing to dir = "+cur_dir;
        chdir(cur_dir);
        #for i in env_files:
        #    if  path.exists(work_dir+"/"+i):
        #        system("ln -sf "+work_dir+"/"+i+" . ");
        #        system("(echo -n "+i+" ; cat "+workdir+"/"+i+" >> run.log");
        my_env = environ;
        my_env["PATH"] = wrappath + ":" + my_env["PATH"];
        num_negs=None
        f=open(test_dir+"/configuration-func-repair");
        for line in f:
            if '--neg-tests' in line:
                x=line.split()
                num_negs=int(x[-1])
                f.close()
                break;
        if num_negs==None:
            f.close();
            num_negs=1

        for i in ids:
            logfile="run.log."+str(i)
            test_id=int(i)
            test_sid=None
            if test_id >= num_negs:
                val=test_id-num_negs+1;
                test_sid="p%d" %(val);
            else:
                val=test_id+1;
                test_sid="n"+str(val);

           #ret = subprocess.call(["timeout 12s sanity_prophet.bash " + i + " 1>/dev/null 2>/dev/null"], shell = True, env = my_env);
            cmd="timeout 12s " + testscript + " " + chal + " " + test_sid + " " + test_dir + " 1>/dev/null 2>/dev/null";
            debug_cmd= testscript + " " + chal + " " + test_sid + " " + test_dir + " >> "+logfile+" 2>&1 ";
            #ret = subprocess.call(["timeout 12s ./test.sh " + challenge_name + " " + i + " 1>/dev/null 2>/dev/null"], shell = True, env = my_env);
            #x=subprocess.Popen("(echo -n '===================\n[START] MUTANT_ID:';cat "+test_dir+"/MUTANT_ID; echo  '\n"+debug_cmd+"\n') >> "+logfile, shell = True, env = my_env);
            x=subprocess.Popen("echo '\n"+debug_cmd+"\n' >> "+logfile, shell = True, env = my_env);
            x.wait();
            #ret = subprocess.call(debug_cmd, shell = True, env = my_env);
            #print "\n- Command = "+" ".join(debug_cmd)
            #print "- CWD = "+getcwd();
            ret = subprocess.Popen(debug_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env = my_env);
            ret.wait();
            if (ret.returncode == 0):
                print i,
            #x=subprocess.Popen("(echo -n '[END] MUTANT_ID:';cat "+test_dir+"/MUTANT_ID; echo  '\n"+debug_cmd+"\n=> "+str(ret.returncode)+"') >>  "+logfile, shell = True, env = my_env);
            x=subprocess.Popen("echo  '\n"+debug_cmd+"\n=> "+str(ret.returncode)+"' >>  "+logfile, shell = True, env = my_env);
            x.wait();
            x=subprocess.Popen("cat "+logfile+" >> run.log; rm -f "+logfile, shell = True, env = my_env);
            x.wait();
        chdir(ori_dir);
        exit(0);
        #for i in env_files:
        #    system("echo os.unlink("+cur_dir+"/"+i+") >> run.log");
        #    os.unlink(cur_dir+"/"+i);

