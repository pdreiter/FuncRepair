#!/bin/bash

SCRIPTDIR=$(dirname -- $(realpath -- ${BASH_SOURCE[0]}))
EVALID=$1
evaldir=decomp_eval$EVALID
CBLIST=$SCRIPTDIR/decomp_xlist

d=decomp_eval-results$EVALID
mkdir -p $d
logdir=$evaldir/logs
recomplogdir=$evaldir/recomp/logs
decomp_target=decomp_targets
for cb in $(cat $CBLIST); do
 (
    echo "CB,FUNC-ID,FUNC-NAME,PRD-STATUS"
    for LOG in $(ls $logdir/$cb.*.log); do 
       FID=$(echo $LOG | perl -p -e's/.*\.(\d+)\.log/$1/')
       recompLOG=$recomplogdir/run.$cb.$FID.log
       myfunc=$(cat $decomp_target/$cb.target_list.$FID | perl -p -e's/.*,//g');
       if (( $(egrep -c -w 'decompilation : FAILED' $LOG)>0 )); then
          echo "$cb,$FID,$myfunc,failed_Decomp"
       elif (( $(egrep -c -w 'recompilation : FAILED' $LOG)>0 )); then
            echo "$cb,$FID,$myfunc,failed_Recomp"
       elif (( $(egrep -c -w 'test-equivalence : FAILED' $LOG)>0 )); then
            echo "$cb,$FID,$myfunc,failed_TestEquiv"
       elif (( $(egrep -c -w 'test-equivalence : PASSED' $LOG)>0 )); then
            echo "$cb,$FID,$myfunc,passed_all"
       else
            echo "$cb,$FID,$myfunc,UNKNOWN"
       fi
       >&2 echo "[Func-eval][function] $cb.$FID"
    done
 ) > $d/$cb.recompile.log
    echo "[Func-eval][COMPLETED] $cb"
done
echo "[Func-eval][COMPLETED] ALL FUNCTIONS DONE"

(echo "CB,C,Total,Fail(decomp),Pass(decomp),Fail(recomp),Pass(recomp),Fail(test-equiv),Pass(test-equiv)";
for i in $(ls $d/*.recompile.log); do 
  (( total=$(cat $i | wc -l )-1 )); 
  decomp_fail=$(grep -c 'failed_Decomp' $i); 
  recomp_fail=$(grep -c 'failed_Recomp' $i); 
  testeq_fail=$(grep -c 'failed_TestEquiv' $i); 
  testeq_pass=$(grep -c 'passed_all' $i); 
  (( recomp_pass=$testeq_pass+$testeq_fail ))
  (( decomp_pass=$recomp_pass+$recomp_fail ))
  cb=$(echo $i | sed "s/$d\///;s/\.recompile\.log//"); 
  cc=$(find $CGC_CB_DIR/challenges/$cb/ -type f -name "*.cc"); 
  if [[ -z "$cc" ]]  ; then 
    c_src="C"; 
  else 
    c_src="C++"; 
  fi; 
  echo "$cb,$c_src,$total,$decomp_fail,$decomp_pass,$recomp_fail,$recomp_pass,$testeq_fail,$testeq_pass"; 
done) > decomp.results.updated_decomp.csv
