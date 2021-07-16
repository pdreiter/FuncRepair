#!/usr/bin/env python2
from sys import argv
from os import path, chdir, getcwd, environ, makedirs, symlink
from tester_common import extract_arguments
import subprocess
import getopt
import random
import shutil
import shlex

def compileit(out_dir, compile_only = False, config_only = False,chal="default",script_dir=None):
    ori_dir = getcwd();

    my_env = environ;
    my_env['PRD_BASE_DIR'] = "."

    top_src_dir=out_dir+"/cb_src"
    src_dir=top_src_dir+"/"+chal
    build_dir=out_dir+"/build"
    #build_dir=out_dir
    inc_dir=top_src_dir+"/include"

    # this path relies on the fact that this script resides in <CGC_ROOT>/prophet/
    base_dir=path.dirname(script_dir)
    tools_dir=base_dir+"/tools/python3"
    poller_dir=base_dir+"/polls/"+chal+"/poller"
    if not path.exists(poller_dir):
        poller_dir=base_dir+"/challenges/"+chal+"/poller"

    profile_dir=True if "/profile" in path.abspath(out_dir) else False
    compiler="gcc"
    compiler_pp="g++"

    # the way that Prophet copies over the src directory
    # i.e. cp challenges/<dir> <dest_dir>/src 
    # breaks compilation - reorganizing to fix it
    if not path.exists(top_src_dir):
        tmpdir="/tmp/"+chal+str(random.randint(1,1000))
        # move the original source dir to a random tmp dir
        shutil.move(out_dir,tmpdir)
        # make the <out_dir>/cb_src
        makedirs(top_src_dir)
        # then move the tmpdir to <out_dir>/cb_src/<CHALLENGE>
        shutil.move(tmpdir,src_dir)
        shutil.copy(script_dir+"/CMakeLists.txt",top_src_dir)
        print("Copying "+script_dir+"/CMakeLists.txt to "+top_src_dir)
        chdir(out_dir)
        symlink(src_dir+"/src","src")
        symlink(src_dir+"/lib","lib")
        symlink(tools_dir,"tools")
        symlink(poller_dir,"poller")
    if not path.exists(build_dir):
        makedirs(build_dir)
    if not path.exists(inc_dir):
        # copy the include dir to <out_dir>/cb_src/include
        shutil.copytree(base_dir+"/include",inc_dir)

    chdir(build_dir);

    if not compile_only:
        if not path.exists(top_src_dir+"/CMakeLists.txt"):
            shutil.copy(script_dir+"/CMakeLists.txt",top_src_dir)
            print("Copying "+script_dir+"/CMakeLists.txt to "+top_src_dir)
        cfg="cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "+\
            "-DCMAKE_VERBOSE_MAKEFILE=ON "+\
            "-DCMAKE_C_COMPILER='"+compiler+"' "+\
            "-DCMAKE_ASM_COMPILER='"+compiler+"' "+\
            "-DCMAKE_CXX_COMPILER='"+compiler_pp+"' "+\
            "-DBUILD_SHARED_LIBS=ON "+\
            "-DBUILD_STATIC_LIBS=OFF "+\
            "-DBINARY="+chal+" "+top_src_dir
        #    "-DCMAKE_C_COMPILER=clang "+\
        #    "-DCMAKE_ASM_COMPILER=clang "+\
        #    "-DCMAKE_CXX_COMPILER=clang++ "+\
        #    "-DCMAKE_C_COMPILER='"+script_dir+"/cc/clang' "+\
        #    "-DCMAKE_ASM_COMPILER='"+script_dir+"/cc/clang' "+\
        #    "-DCMAKE_CXX_COMPILER='"+script_dir+"/cc/clang++' "+\
        cfg_cmd=shlex.split(cfg)
        ret = subprocess.call(cfg_cmd, env = my_env);
        #if profile_dir:
        for i in ["link.txt","flags.make","build.make"]:
                f=chal+"/CMakeFiles/"+chal+".dir/"+i
                remove_hardpath="perl -pi -e's#/usr/bin/gcc#gcc#g;s#/usr/bin/g++#g++#g;' "+f
                trn_cmd=shlex.split(remove_hardpath)
                ret = subprocess.call(trn_cmd, env=my_env);

        chdir(out_dir)
        with open("Makefile.cgc","w") as f:
            f.write("include build/"+chal+"/Makefile\n")
            f.write("tmp:\n\t")
            f.write("cd build\n\t")
            f.write("make\n\t")
            f.close()
        chdir(build_dir);


    if not config_only:
        #ret = subprocess.call(["make"], env = my_env);
        build_cmd=shlex.split("cmake --build .")
        ret = subprocess.call(build_cmd, env = my_env);
        if ret != 0:
            print "Failed to make!";
            chdir(ori_dir);
            exit(1);
        shutil.copy(chal+"/"+chal,out_dir)
        import glob
        for i in glob.glob(chal+"/"+"*.pov"):
            shutil.copy(i,out_dir)

    chdir(ori_dir);

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

    script_dir=path.dirname(argv[0])
    compileit(out_dir, compile_only, config_only,challenge,script_dir);
    build_subdir="build/"+challenge
    if dryrun_src != "":
        (builddir, buildargs) = extract_arguments(out_dir, dryrun_src, build_subdir);
        if len(args) > 1:
            out_file = open(args[1], "w");
            print >> out_file, builddir;
            print >> out_file, buildargs;
            out_file.close();
        else:
            print builddir;
            print buildargs;
