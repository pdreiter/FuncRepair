#!/bin/bash

mycbs=()
index=0
src="genprog"
logdir="perf"
for i in $@; do  
    echo $i
    if  [[ "$i" == "--src="* ]]; then
        src=$(echo $i | sed 's/\-\-src=//')
    elif  [[ "$i" == "--logdir="* ]]; then
        logdir=$(echo $i | sed 's/\-\-logdir=//')
    elif [[ "$i" == "-h"  ||  "$i" == "-help"  ||  "$i" == "--help" ]]; then
        echo ""
        echo "Description: $0 CB_0 CB_1 ... CB_N "
        echo ""
        echo "This script generates performance test scripts from CBs' test scripts"
        echo "  specified challenge binaries: CB_i, for i=0 to N"
        echo ""
        echo ""
        echo "New performance test script is called 'test_perf.sh'"
        echo ""
        echo "Exiting..."
        exit 1
    else
       mycbs+=($i)
    fi  
    (( index+= 1 ))
done;

for cb in ${mycbs[*]}; do


if [[ ! -e "$src/$cb/test.sh" ]]; then 
    echo "ERROR: 'test.sh' does not exist in '$src/$cb'"
    echo "skipping..."
    continue
else
    # looks like performance log isn't generated in sigterm cases, soooo, not going to add it to negative test cases either, although failing signature disappears
    #perl -p -e'if(/^([pn]\d+)\)/){ $cur_case=$1; } if(/^(\s+)(python[23]\s*)?((\.\/)?(tools\/cb-replay.*\.py.*))$/){ $cmd="$1$5"; if ($cur_case=~/^n/){ $prefix="/bin/bash -c "; } else { $prefix=""; }; $new_line="$cmd --dbi \"$prefix/usr/bin/perf stat -o $cur_case.perf.log \"\n"; $_=$new_line; $cur_case=""; }' $src/$cb/test.sh > $src/$cb/test_perf.sh
    perl -p -e"\$outdir=\"$logdir\";"'if(/^([pn]\d+)\)/){ $cur_case=$1; } if(/^(\s+)(python[23]\s*)?((\.\/)?(tools\/cb-replay.*\.py.*))$/){ $space="$1";$test="$5"; $setup_cmd="${space}mkdir -p $outdir;\n"; $new_line="${setup_cmd}${space}${test} --dbi \"$prefix/usr/bin/perf stat -o $outdir/$cur_case.perf.log \"\n"; $_=$new_line; $cur_case=""; }' $src/$cb/test.sh > $src/$cb/test_perf.sh
  chmod +x $src/$cb/test_perf.sh 
  if [[ -z $done ]]; then done=""; else done+="\n";fi
  done+="$cb"
fi


done
echo -e "Completed Performance test conversion for:\n$done"
