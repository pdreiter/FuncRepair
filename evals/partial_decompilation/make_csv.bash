#!/bin/bash

ID=$1
LOGDIR=$PWD/decomp_eval$ID/logs
RESULTS=$PWD/decomp_eval$ID.results.log;
echo "program.func_id,lang,decompilation,basic,recompilation,recompilation-w-asm,test-equivalence"> $RESULTS;
for i in $(ls $LOGDIR); do  
    ID=$(echo $i | sed 's/\.log//'); 
    PROG=$(echo $ID | sed 's/\./ /' | awk '{print $1}'); 
    LANG="C"; 
    if (( $(egrep -c -w $PROG cpp_xlist) > 0 )); then 
        LANG=CPP; 
    fi; 
    line="$ID,$LANG";
    for j in "decompilation :" "basic :" "recompilation :" "recompilation-w-asm :" "test-equivalence :"; do 
        res="N/A";
        if (( $(egrep -w "$j" $LOGDIR/$i | wc -l) > 0 )); then 
            res=$(egrep -w "$j" $LOGDIR/$i | tail -n 1 | awk '{print $3}');
        fi ; 
        line="$line,$res"; 
    done;
    echo $line >> $RESULTS; 
done; 
cp $RESULTS ../partial_decompilation.results.csv 
