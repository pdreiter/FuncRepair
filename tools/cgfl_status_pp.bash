#!/bin/bash
destdir=$1
cb=$2
seed=$3

for i in $cb; do 
	if [[ ! -e $destdir/build/$i ]]; then
	   continue
	fi
    if [[ ! -e patched_functions/${i}_info ]]; then 
	   echo -e "\n$i : no ground truth"; continue; 
	elif [[ ! -e $destdir/cgfl/cgfl_rank/$i/$i.top_rank.list ]]; then 
	   echo -e "\n$i : no cgfl data"; continue; 
	elif [[ $(file $destdir/cgfl/cgfl_rank/$i/$i.top_rank.list | awk '{print $NF}') == "empty" ]]; then
	   echo -e "\n$i : no cgfl data"; continue; 
	fi; 
	missing=0;cnt=0; missing_fns=""; 
    rank_size=$(wc -w $destdir/cgfl/cgfl_rank/$i/$i.*seed_$seed.results.log | head -n 1 | awk '{print $1}')
	for j in $(cat patched_functions/${i}_info | perl -p -e's/^[^:]+: */ /;s/\n$//' | perl -p -e's/$/\n/;s/(\sstruct|struct\s)//g'); do 
       susp_file=$destdir/build/$i/susp-fn.log
       [[ ! -e $susp_file ]] && susp_file=$destdir/build/$i/susp-default.std.log
	   num=$(egrep -c -w $j $destdir/cgfl/cgfl_rank/$i/$i.top_rank.list);
       total_fns=0
       if (( $(egrep -c 'Ranking per function with collection of ties' $susp_file)>0 )); then
          (( total_fns=$(egrep -a2 'Ranking per function with collection of ties' $susp_file | head -n 1 | sed 's/|/ /g' | awk '{print $1}')+1 ))
       else
          (( total_fns=$(tail -n 1 $susp_file | sed 's/|/ /g' | awk '{print $1}')+1 ))
       fi
	   if (( $num==0 )); then 
		  rank="undefined"
		  if (( $(egrep -wc "^$j" $susp_file) > 0 )); then 
              rank=$(egrep -w "^$j" $susp_file | perl -p -e"s/\s*\|/,/g;s/$j\s*,//;s/\s*//;s/,/, /g")
		  elif (( $(egrep -wc "$j" $susp_file) > 0 )); then 
              rank=""
              for susp in $(egrep -w "$j" $susp_file | sed 's/|/ /g' | awk '{print $1}'); do
                  #(( rank=$(egrep -w "$j" $susp_file | tail -n 1 | sed 's/|/ /g' | awk '{print $1}')+1 ))
                  rnk=$(( $susp+1 ))
                  if (( ${#rank}<=1 )); then rank="[ $rnk"; else rank=$rank", $rnk"; fi
                  #echo "SUSP Rank=> [$rnk] $rank"
              done
              rank=$rank"]"
		  fi
	      missing_fns+="\n - $j [ susp_ranks : $rank ] [ $rank_size / $total_fns ]"; (( missing+=1 )); 
          x=$(cat $destdir/build/$i/info.json | perl -p -e"if(/(\"$j\": \{\"num_instructions\": \d+, \"num_calls\": \d+, \"num_bytes\": \d+)(.*)/){ print \"\$1\}\"; }; undef \$_; ")
          missing_fns+="\n\t$x"
	   fi; 
	   (( cnt+=1 )); 
	done; 
	(( found=$cnt-$missing ));  
	result="$i : $found / $cnt [ $rank_size / $total_fns ]"; 
	if (( $found==$cnt )); then
		result="$result [ COMPLETE_SUCCESS ]"
	elif (( $found>0 )); then
		result="$result [ PARTIAL_SUCCESS ]"
	else
		result="$result [ FAILED ]"
	fi
	echo -e "\n$result"
	if (( $missing > 0 )); then 
	   echo -e "missing : $missing_fns"; 
	fi; 
done 

