#!/usr/bin/env python3

#--------------------------------------------------------------------
# 
#--------------------------------------------------------------------

# need to comment out floatn-common lines

from sys import argv,stderr,exit
from os import system, environ, path
from pathlib import Path
import re
import subprocess as subp

exe=argv[0]
inputF=argv[1]
outputF=argv[2]
default_dont_instr=["__uint(16|32|64)_identity","__bswap_(16|32|64)","__prd_init","__prd_exit"]


if not Path(inputF).is_file():
    print("ERROR: File {} does not exist! Cannot proceed.".format(inputF),file=stderr,flush=True);
    exit(-1);

egrep_cmd="egrep 'func-repair-fn-name' configuration-func-repair | awk '{print $NF}' |sort -u"
x=subp.Popen(egrep_cmd,stdout=subp.PIPE,stderr=subp.PIPE,shell=True);
stdout,stderr=x.communicate()
replace_fn=stdout.decode('utf-8').split()[0]

egrep_cmd="egrep '(blacklist-src-functions|do-not-instrument)' configuration-func-repair | awk '{print $NF}'"
x=subp.Popen(egrep_cmd,stdout=subp.PIPE,stderr=subp.PIPE,shell=True);
stdout,stderr=x.communicate()
dont_instrument=stdout.decode('utf-8').split()
dont_instrument+=default_dont_instr
dont_instr="(^|\s|\*)("+"|".join(dont_instrument)+")\s*\(?"
#print("entry:{}\ndont_instr:{}\n".format(replace_fn," ".join(dont_instrument)))
print("entry function: "+replace_fn+"\ndont_instrument: "+dont_instr)
    
replace_fn_rex=re.compile("(^|\s|\*)("+replace_fn+")\s*\(?");
floatn_rex=re.compile("^typedef\s+(long )?(double|float)\s+_Float(32|64)x?");
prof_track_rex=re.compile("^\s*__prof_track");
dont_instr_rex=re.compile(dont_instr);
comment1_rex=re.compile("//.*$");
comment2open_rex=re.compile("/\*.*$");
comment2close_rex=re.compile("^.*\*/");


inBLFunc=False
inComment=False
inEntry=False
func_content=""

outFH= open(outputF,encoding='utf-8',mode='w',errors='replace');

with open(inputF,encoding='utf-8',mode='r',errors='replace') as x:
    line=x.readline();
    while line:
        #print("line: '{}'".format(line.rstrip()))
        if not inBLFunc:
            f1=floatn_rex.match(line.rstrip());
            f2=dont_instr_rex.search(line.rstrip());
            f3=replace_fn_rex.search(line.rstrip());
            if f1:
                line="//"+line;
            elif f2:
                inBLFunc=True;
                func_content="";
                nocomment_func="";
                if f3:
                    inEntry=True;
        if inBLFunc:
            func_content+=line;
            nocomment_line=line;
            f3=comment1_rex.search(nocomment_line)
            if f3:
                nocomment_line=re.sub("//.*$","",nocomment_line)
            f4=comment2open_rex.search(nocomment_line)
            f5=comment2close_rex.search(nocomment_line)
            if f4 and f5 and not inComment:
                nocomment_line=re.sub("/\*.*\*/","",nocomment_line)
            elif f4 and f5 and inComment:
                nocomment_line=re.sub("^.*\*/","",nocomment_line)
                nocomment_line=re.sub("/\*.*$","",nocomment_line)
            elif not f4 and f5 and inComment:
                nocomment_line=re.sub("^.*\*/","",nocomment_line)
                inComment=False
            elif f4 and not f5 and not inComment:
                nocomment_line=re.sub("/\*.*$","",nocomment_line)
                inComment=True
            elif not f4 and not f5 and inComment:
                nocomment_line=re.sub("^.*$","",nocomment_line)
            elif not f4 and not f5 and not inComment:
                # standard line in function
                inComment=False;
            else:
                print("Invalid state:\nFunction:[{}],[/*,*/,inComment]=[{},{},{}]".format(func_content,f4,f5,inComment),flush=True);
             
            #print("Checking for __prof_track in function: '{}'".format(nocomment_line));
            f6=prof_track_rex.search(nocomment_line);
            found_asm=False
            if f6:
                nocomment_line=re.sub("__prof_track","//__prof_track",nocomment_line)
                line=re.sub("__prof_track","//__prof_track",line)
            if inEntry:
                #if re.search("(^|\s)asm\s*",nocomment_line) or re.search("(^|\s)return\s*(\w+\s*)?;",nocomment_line):
                if re.search("(^|\s)asm\s*",nocomment_line):
                    found_asm=True
                    #print("Found 'asm':'{}'".format(nocomment_line));
                    nocomment_line="    __prof_exit();"+nocomment_line
                    line="    __prof_exit();\n"+line
                if not found_asm and re.search("^\s*return\s*(\w+)?;\s*$",nocomment_line):
                    nocomment_line="    __prof_exit();"+nocomment_line
                    line="    __prof_exit();\n"+line
            nocomment_func+=nocomment_line.rstrip();
            open_brace=nocomment_func.count("{");
            close_brace=nocomment_func.count("}");
            statements=nocomment_func.count(";");
            if open_brace==close_brace and open_brace>0:
                inBLFunc=False
                inEntry=False
            elif open_brace==close_brace and statements>0:
                inBLFunc=False
                inEntry=False
                
        outFH.write(line);
        line=x.readline();
