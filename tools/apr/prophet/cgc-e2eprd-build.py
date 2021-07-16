#!/usr/bin/env python2
#
# 
# this file is based on and extended from the build and test scripts 
# provided by Prophet, but specific to CGC CB PRD build flow
# Extended by pdreiter on 10/2020
#
# Copyright (C) 2016 Fan Long, Martin Rianrd and MIT CSAIL 
# Prophet
# 
# This file is part of Prophet.
# 
# Prophet is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Prophet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Prophet.  If not, see <http://www.gnu.org/licenses/>.
from sys import argv



from sys import argv
from os import path, chdir, getcwd, environ
from tester_common_prd import extract_arguments
import subprocess
import getopt
import random

src_type="c"
#def fix_source(sour):
#    f = open(sour, "r");
#    lines = f.readlines();
#    f.close();
#    f = open(sour, "w");
#    for line in lines:
#        f.write(line);
#        if line.find("ldcline += fbc.extopt.ld") != -1:
#            f.write('\tldcline += " -l c "\n');
#    f.close();

def genTmpFilename():
    cond = True;
    while cond:
        ret = "/tmp/cgc_pclang_";
        for i in range(0, 8):
            ret = ret + str(random.randint(0, 9));
        if src_type != "cpp":
            ret = ret + ".c";
        else:
            ret = ret + ".cpp";
        cond = path.exists(ret);
    return ret;


def compileit(out_dir, compile_only = False, config_only = False,chal="default"):
    ori_dir = getcwd();
    chdir(out_dir);
    basedir=path.basename(path.realpath(out_dir))
    profile=False
    if basedir == "profile":
        # this is a profile run
        profile=True
    with open("run.log","w+") as f:
        f.write("==================================");
    #if (path.exists("run.log")):
    #    with open("run.log","w+") as f:
    #        f.write("==================================");
    #    os.remove("run.log");
    my_env = environ;
    my_env['PRD_BASE_DIR'] = "."
    #my_env['CC']="gcc"

#    if not compile_only:
#    if (path.exists("fbc-src/src/compiler/fbc_linux.bas")):
#            fix_source("fbc-src/src/compiler/fbc_linux.bas");
#        ret = subprocess.call(["./configure"], shell = True, env = my_env);
#        if (ret != 0):
#            print "Failed to run configure!";
#            chdir(ori_dir);
#            exit(1);
    #command="/usr/bin/env printenv";
    #command="/usr/bin/env realpath "+my_env['CC']
    #log_cmd(chal,command,my_env,"w");
    command="make -f Makefile.prophet prophet_run_hook"
    if profile:
        temp1=genTmpFilename();
        temp2=genTmpFilename();
        temp3=genTmpFilename();
        temp4=genTmpFilename();
        tmpstring= "TMP1={} TMP2={} TMP3={} TMP4={}".format(temp1,temp2,temp3,temp4);
        command="/usr/bin/make -f Makefile.prophet "+tmpstring+" PROPHET_PROFILE=1 prophet_profile prophet_prof_hook";
        import os
        os.system("perl -pi -e'if(/(Checking for unbound|check)/){ undef $_; }' Makefile.genprog")
    print "Running command: "+command+"\n in this directory : "+out_dir;
    if not config_only:
        #ret = subprocess.call(["make -f Makefile.genprog hook funcinsert"], env = my_env);
        ret=log_cmd(chal,command,my_env,"a");
        if ret != 0:
            print "Failed to make!";
            log_msg(chal,"Failed to make!\n","a");
            chdir(ori_dir);
            exit(1);
    chdir(ori_dir);

def log_msg(chal,message,mode):
    with open(chal+".build.log",mode) as f:
        f.write(message);
        f.close()

def log_cmd(chal,command,my_env,mode):
    lcmd=command.split();
    proc = subprocess.Popen(lcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env = my_env);
    stdoutv,stderrv=proc.communicate();
    ret=proc.wait();
    log_msg(chal,stdoutv,mode);
    log_msg(chal,stderrv,"a");
    if ret != 0:
        log_msg(chal,"| ERROR | command failed => ["+command+"]\n","a");
    return ret

if __name__ == "__main__":
    #deps_dir = getcwd() + "/cgc-deps"
    deps_dir = getcwd() + "/libsrc";

    compile_only = False;

    opts, args = getopt.getopt(argv[1:],'cd:hlp:r:xe:');
    dryrun_src = "";

    print_fix_log = False;
    print_usage = False;
    config_only = False;
    challenge = "";
    for o, a in opts:
        if o == "-d":
            dryrun_src = a;
        elif o == "-p":
            if a[0] == "/":
                deps_dir = a;
            else:
                deps_dir = getcwd() + "/" + a;
        elif o == "-e":
            challenge = a;
        elif o == "-x":
            config_only = True;
        elif o == "-c":
            compile_only = True;
        elif o == "-l":
            print_fix_log = True;
        elif o == "-h":
            print_usage = True;

    if (len(args) < 1) or (print_usage):
        print "Usage: cgc-build.py <directory> [-d src_file | -l] [-h]";
        exit(0);

    out_dir = args[0];
    if (path.exists(out_dir)):
        print "Working with existing directory: " + out_dir;
    else:
        print "Non-exist directory";
        exit(1);

    compileit(out_dir, compile_only, config_only,challenge);
    if dryrun_src != "":
        (builddir, buildargs) = extract_arguments(out_dir, dryrun_src);
        if len(args) > 1:
            out_file = open(args[1], "w");
            print >> out_file, builddir;
            print >> out_file, buildargs;
            out_file.close();
        else:
            print builddir;
            print buildargs;
