#!/bin/bash

#--------------------------------------------------------------------------------------------
# script: sanity.bash
# author: pdreiter
# description: the purpose of this script is to verify a binary's quality against local test content
#--------------------------------------------------------------------------------------------
# NOTE: Expecting that this script is run in Challenge Binary build directory 
#       (or where genprog and test content as well as binaries exist)
#--------------------------------------------------------------------------------------------
# example command line:
#   cd $CGC_CB_DIR/build32/challenges/<CB>
#   $CGC_CB_DIR/sanity.bash <binary_file_name> -help
#
#Usage[1]: ./sanity.bash <executable> [-regression]
#Usage[2]: ./sanity.bash <executable> <test> [num test runs (default:10)]
#--------------------------------------------------------------------------------------------

#NUM=10;
#EXE=Message_Service.trampoline.bin ;
EXE=$1
TEST=$2
run_regression=0
pass_fail=0
test_script="./test.sh"

help_msg(){
   echo -e "Usage[1]: $0 <executable> [-regression]"
   echo -e "Usage[2]: $0 <executable> <test> [num test runs (default:10)]"
   echo -e "-help    Prints this message"
   echo -e "\n\tThere are two use cases for this script: regression[1] and stress testing[2]"
   echo -e "\nregression[1]:"
   echo -e "\tDefault behavior runs <executable> against all available test cases"
   echo -e "\tIf -regression|-reg is supplied, then <executable> and the provided repair <executable>_patch is run against all available test cases"
   echo -e "\tIf both pass all positive tests and appropriately behave wrt negative tests, then script exits with 0 value, else 1 (_patch should pass all negative tests, while <executable> should fail)"
   echo -e "\tFirst run: <executable> "
   echo -e "\tSecond run: <executable>_patch\n"
   echo -e "\nstress testing[2]:"
   echo -e "\t<test> is run on an <executable> for [num test runs] value."
   echo -e "\tDefault value for [num test runs] is 10"
   exit
}

run_reg() {
   local EXE=$1
   local TEST=""
   local EXPECTING_NEG_TO_PASS=$2
   echo "Regression: $EXE"
   if [ $EXPECTING_NEG_TO_PASS -eq 1 ] ; then
      echo "Expecting negative tests to PASS"
   else
      echo "Expecting negative tests to FAIL"
   fi
   local j=0
   pos=$(egrep 'pos\-tests' configuration-func-repair | awk '{print $NF}')
   for i in $(seq 1 $pos); do
      TEST="p$i"
      $test_script $EXE $TEST > /dev/null;
      x=$?
      val="PASSED"
      if [[ $x -ne 0 ]]; then
      (( j+=1 ));
      val="FAILED"
      fi;
      echo -e "[$i] status $x => $val $TEST TEST!";
   done

   local k=0
   local negofail=0
   local neg=$(egrep 'neg\-tests' configuration-func-repair | awk '{print $NF}')
   for i in $(seq 1 $neg); do
      TEST="n$i"
      out=$($test_script $EXE $TEST ; echo $?) 
	  x=$(echo $out | awk '{print $NF}')
	  negotiation_fail=$(echo $out | perl -p -e's/^.*\(\-?\d+,\s+\-?\d+,\s+(True|False)\).*$/$1/')
	  if [ $negotiation_fail == "False" ]; then 
          val="PASSED"
          if [[ $x -ne 0 ]]; then
              (( k+=1 ));
              val="FAILED"
          fi;
	  else
          val="NEGOTIATION_FAILED"
          (( negofail+=1 ));
	  fi;
      echo -e "[$i] status $x => $val $TEST TEST!";
   done
   echo "# of failed POSITIVE tests $j of $pos"
   echo "# of failed NEGATIVE tests $k of $neg"
   echo "# of negotiation_failed NEGATIVE tests $negofail of $neg"
   ret=0
   if [ $j -ne 0 ]; then
       (( ret=2 ));
   fi
   num_neg_passing=0
   if [ $EXPECTING_NEG_TO_PASS -eq 0 ]; then 
       num_neg_passing=$neg
   fi
   echo -e "Expecting $num_neg_passing Negative tests to fail"
   if [ $k -ne $num_neg_passing ]; then
       (( ret+=1 ));
   fi
   # return 0 : all positive tests pass and negative tests behave as expected
   # return 1 : all positive tests pass and negative tests do not behave as expected
   # return 2: any positive test failed and negative tests behave as expected
   # return 3: any positive test failed and negative tests do not behave as expected
   echo -e "Returning $ret\n"
   return $ret
}

args=("$@")
(( len=$# ))
(( $# == 0 )) && help_msg
(( $# > 0 )) && \
(( i = 0 ))
while (( i < $len )); do
    if [[ "${args[$i]}" == "-help" || "${args[$i]}" == "-h" || "${args[$i]}" == "--help" ]]; then
       help_msg
	fi
	(( i+=1 ))
done

if [[ -z $TEST ]]; then
#Usage[1]: ./sanity.bash <executable>
   # not expecting negative tests to pass
   run_reg "$EXE" "0" ;
   
elif [[ "$TEST" == "-reg"* ]]; then 
#Usage[1]: ./sanity.bash <executable> -regression
   # not expecting negative tests to pass
   run_reg "$EXE" "0";
   stat1=$ret
   patch="${EXE}_patched"
   # expecting negative tests to pass with _patched 
   run_reg "$patch" "1";
   stat2=$ret
   exit_val=0
   echo "$stat1 => $stat2"
   if [ $stat1 -ne 0 ]; then
      (( exit_val+=$stat1 ));
   # return 0 : all positive tests pass and negative tests behave as expected
   # return 1 : all positive tests pass and negative tests do not behave as expected
   # return 2: any positive test failed and negative tests behave as expected
   # return 3: any positive test failed and negative tests do not behave as expected
      if [ $stat1 -eq 1 ]; then 
      echo "${EXE} [FAIL] : all positive tests [PASS], some negative tests [PASS]"
      elif [ $stat1 -eq 3 ]; then 
      echo "${EXE} [FAIL] : some positive tests [FAIL], some negative tests [PASS]"
      elif [ $stat1 -eq 2 ]; then 
      echo "${EXE} [FAIL] : some positive tests [FAIL], all negative tests [FAIL]"
      fi
   else
      echo "${EXE} [PASS] : all positive tests [PASS], all negative tests [FAIL]"
   fi
   (( exit_val=4*$exit_val ));
   if [ $stat2 -ne 0 ]; then
      (( exit_val+=$stat2 ));
      if [ $stat2 -eq 1 ]; then 
      echo "${patch} [FAIL] : all positive tests [PASS], some negative tests [FAIL]"
      elif [ $stat2 -eq 3 ]; then 
      echo "${patch} [FAIL] : some positive tests [FAIL], some negative tests [FAIL]"
      elif [ $stat2 -eq 2 ]; then 
      echo "${patch} [FAIL] : some positive tests [FAIL], all negative tests [PASS]"
      fi
   else
      echo "${patch} [PASS] : all positive tests [PASS], all negative tests [PASS]"
   fi
   (( exit_val=4*$exit_val ));
   if [ $stat1 -ne 0 ]; then
   (( exit_val+=2 ));
   fi
   if [ $stat2 -ne 0 ]; then
   (( exit_val+=1 ));
   fi

   exit $exit_val;

else
#Usage[2]: ./sanity.bash <executable> <test> [num test runs (default:10)]
echo "Testing $EXE $TEST";
NUM=$3;
if [[ -z $NUM ]]; then
NUM=10
fi

DEBUG=$4;
j=0;

for i in $(seq 1 $NUM); do 
x=0
if [[ -z $DEBUG && $TEST == "p"* ]]; then 
$test_script $EXE $TEST > /dev/null
x=$?
else
$test_script $EXE $TEST 
x=$?
fi
val="PASSED"
if [[ $x -ne 0 ]]; then
(( j+=1 ));
val="FAILED"
fi;
echo -e "\n[$i] status $x => $val $TEST TEST!";
done;
echo "# of failed $TEST tests $j of $i"
fi
