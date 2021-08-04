#!/bin/bash
filelist=$1
destdir=$2
if [[ -z $destdir ]]; then 
destdir="prd_e2e"
fi
seed=
if [[ ! -z $3 ]]; then 
seed=$3
fi
scriptdir=$(dirname $0)

log="$destdir.cgfl_status.log"
for i in $(cat $filelist); do 
    $scriptdir/cgfl_status_pp.bash $destdir $i $seed
done > $log

perfect=$(egrep -c -rw 'COMPLETE_SUCCESS' $log)
almost=$(egrep -c -rw 'PARTIAL_SUCCESS' $log)
failed=$(egrep -c -rw 'FAILED' $log)
successes=$(egrep -c -r '(SUCCESS)' $log)
total=$(egrep -c -r '(SUCCESS|FAILED)' $log)
results="\n\nResults for $destdir [seed=$seed]:\n"
results+="Success/Failures over Binaries\n"
results+="----------------------------------\n"
results+="failures          : $failed / $total\n"
results+="success number    : $successes / $total\n"
results+="- complete        : $perfect / $total\n"
results+="- partial         : $almost / $total\n"
results+="\n\nFunction-specific failure breakdown:\n"
results+="----------------------------------\n"
unid_fn=$(egrep '^ -' $log | wc -l)
total_fn=0; for i in $(egrep -r '(SUCCESS|FAILED)' $log| awk '{print $5}'); do ((total_fn+=$i)); done
id_fn=0; for i in $(egrep -r '(SUCCESS|FAILED)' $log| awk '{print $3}'); do ((id_fn+=$i)); done
results+="identified        : $id_fn / $total_fn\n"
results+="unidentified      : $unid_fn / $total_fn\n\n"
no_data=0
out=0
new_results=""
for i in $(egrep '^ -' $log  | egrep undefined  | awk '{print $2}'); do 
    x=$(egrep -a6 -w $i $log | head -n6 | egrep '(SUCCESS|FAIL)' | tail -n 1 | awk '{print $1}');
	neg=$(egrep ":$i " $destdir/cgfl/cgfl_results/$x/tmp/n*.annot|wc -l);
	if (( $neg==0 )); then 
		new_results+=" - $i ($x) : NO DATA\n"
        ((no_data+=1))
	else
		new_results+=" - $i ($x) : OUT ($neg)\n"
        ((out+=1))
	fi
done
bad=$(egrep '^ -' $log  | egrep -v undefined | wc -l)
look_behind=40
for ij in $(egrep '^ -' $log  | egrep -v undefined | awk '{print $2","$6$7}' | sed 's/\/$//'); do
    i=$(echo $ij | perl -p -e's/,.*$//')
    j=$(echo $ij | perl -p -e's/^.*,//;s/\(/+/;s/\)//')
    l=$look_behind
    x=$(egrep -n "^ - $i " $log | sed 's/:/ /g' | awk '{print $1}' | head -n1 | sed 's/ //g')
    over=$(( $x < $look_behind ))
    if [[ $over -eq "1" ]] ; then l=$x; fi
    cb=$(egrep -a$l -w $i $log | head -n$l | egrep '(SUCCESS|FAIL)' | tail -n 1 | awk '{print $1}');
    k=$(egrep -a$l -w $i $log | head -n$l | egrep '(SUCCESS|FAIL)' | tail -n 1 | awk '{print $7}');
    l=$(($j-1))
    new_results+=" - $i ($cb) : NOT TOP-K ($k) [$j:$l]\n"
done
results+=" $no_data - NO DATA : function does not occur in CGFL data for negative tests\n"
results+=" $out - OUT (N): function screened out N times\n"
results+=" $bad - NOT TOP-K (K) [R+T:E]: not in TOP-K (K) results, but in rank R tied with T other functions, effective rank E (R+T-1)\n"
results+="\nfunction information:\n"
results+=$new_results
echo -e $results >> $log
echo -e $results
echo -e "=> RESULTS CAPTURED in '$log'\n"
