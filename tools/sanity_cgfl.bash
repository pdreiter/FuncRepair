#!/bin/bash

#--------------------------------------------------------------------------------------------
# script: sanity_cgfl.bash
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
unset TEST
run_regression=0
pass_fail=0
script_dir=$(dirname $0)
test_script="./test_cgfl.sh"
outdir=$PWD
profile_outdir="$outdir/cgfl_profile"
results_dir="$outdir/cgfl_results"
r_dir="$outdir/r"
MIN_BYTES=50
MIN_INSTRS=

help_msg(){
   echo -e "Usage[1]: $0 <executable> [-regression] [-num_runs=<num>] [--results=<results dir>] [--profile-out=<profile_dir>] [--r-out=<Rscript dir] [--top-k-percent=<decimal percentage>]"
   echo -e "Usage[2]: $0 <executable> --test=<test> [-num_runs=<nums> (default:10)]"
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

args=("$@")
(( len=$# ))
(( $# == 0 )) && help_msg
(( $# > 0 )) && \
(( i = 1 ))
num_runs=1
regression=0
TOP_K=0.25
while (( i < $len )); do
    if [[ "${args[$i]}" == "-help" || "${args[$i]}" == "-h" || "${args[$i]}" == "--help" ]]; then
       help_msg
    elif [[ "${args[$i]}" == "-reg"* ]]; then
       regression=1
    elif [[ "${args[$i]}" == "--test="* ]]; then
       TEST=$(echo ${args[$i]} | perl -p -e's/\-\-test=//')
    elif [[ "${args[$i]}" == "--min-bytes="* ]]; then
       MIN_BYTES=$(echo ${args[$i]} | perl -p -e's/\-\-min-bytes=//')
    elif [[ "${args[$i]}" == "--min-instrs="* ]]; then
       MIN_INSTRS=$(echo ${args[$i]} | perl -p -e's/\-\-min-instrs=//')
    elif [[ "${args[$i]}" == "--results="* ]]; then
       results_dir=$(echo ${args[$i]} | perl -p -e's/\-\-results=//')
    elif [[ "${args[$i]}" == "--top-k-percent="* ]]; then
       #echo -n "Overriding TOP-K from $TOP_K to "
       TOP_K=$(echo ${args[$i]} | perl -p -e's/\-\-top\-k\-percent=//')
       #echo "$TOP_K"
    elif [[ "${args[$i]}" == "--r-out="* ]]; then
       r_dir=$(echo ${args[$i]} | perl -p -e's/\-\-r\-out=//')
    elif [[ "${args[$i]}" == "--profile-out="* ]]; then
       profile_outdir=$(echo ${args[$i]} | perl -p -e's/\-\-profile\-out=//')
    elif [[ "${args[$i]}" == "--out="* ]]; then
       outdir=$(echo ${args[$i]} | perl -p -e's/\-\-out=//')
       results_dir="$outdir/cgfl_results"
       profile_outdir="$outdir/cgfl_profile"
       r_dir="$outdir/r"
    elif [[ "${args[$i]}" == "-num_runs="* ]]; then
       num_runs=$(echo ${args[$i]} | perl -p -e's/\-num_runs=//')
	fi
	(( i+=1 ))
done

reg_log_subdir="$profile_outdir"
mkdir -p $results_dir $profile_outdir $r_dir

cg_annotate() {
   local EXE=$1
   local log_dir=$2
   local TEST=$3
   local FUNC_RE=$4
   local LIBFUNC_RE=$5
   mkdir -p $log_dir/tmp
   echo "callgrind_annotate --include=$CGC_CB_DIR/challenges/$EXE/src --threshold=100 $log_dir/$TEST.cg.out > $log_dir/tmp/$TEST.annot;">> $log_dir/cgfl.bash
   callgrind_annotate --include=$CGC_CB_DIR/challenges/$EXE/src --threshold=100 $log_dir/$TEST.cg.out > $log_dir/tmp/$TEST.annot;
   echo "(echo \"{\"; perl -p -e'if (/^\\s*((\\d+,)*\\d+)\\s+\\S+:([^\\s\\(]+)(\\s+|\\()/){ my (\$func,\$val)=(\$3,\$1); \$val=~s/,//g; print \"\\\"\$func\\\":\$val,\\n\";} undef $_;' $log_dir/tmp/$TEST.annot; echo \"}\") > $log_dir/tmp/$TEST.dict;" >> $log_dir/cgfl.bash 
   (echo "{"; perl -p -e'if (/^\s*((\d+,)*\d+)\s+\S+:([^\s\(]+)(\s+|\()/){ my ($func,$val)=($3,$1); $val=~s/,//g; print "\"$func\":$val,\n";} undef $_;' $log_dir/tmp/$TEST.annot; echo "}") > $log_dir/tmp/$TEST.dict; 
   #echo "cat $log_dir/tmp/$TEST.dict | egrep -w \"(\{|\}|$FUNC_RE)\" > $log_dir/$TEST.dict"
   cat $log_dir/tmp/$TEST.dict | egrep -w "(\{|\}|$FUNC_RE)" | egrep -vw "($LIBFUNC_RE)" > $log_dir/$TEST.dict
   echo "cat $log_dir/tmp/$TEST.dict | egrep -w \"(\\{|\\}|$FUNC_RE)\" | egrep -vw \"($LIBFUNC_RE)\" > $log_dir/$TEST.dict;" >> $log_dir/cgfl.bash
   #cat $log_dir/tmp/$TEST.dict | egrep -w "(\{|\}|$FUNC_RE)"  > $log_dir/$TEST.dict
   #echo "cat $log_dir/tmp/$TEST.dict | egrep -w \"(\\{|\\}|$FUNC_RE)\" > $log_dir/$TEST.dict;" >> $log_dir/cgfl.bash
}

generate_all_dict(){
   local log_dir=$1
   (echo "{";for i in $(cat $log_dir/*.dict | perl -p -e's#:.*##;s#[{}"]##g;if(/^$/){undef $_;}' | sort -u); do echo "\"$i\":0,"; done; echo "}") > $log_dir/all.dict
   echo "(echo \"{\";for i in \$(cat $log_dir/*.dict | perl -p -e's#:.*##;s#[{}\"]##g;if(/^$/){undef \$_;}' | sort -u); do echo \"\\\"\$i\\\":0,\"; done; echo \"}\") > $log_dir/all.dict;" >> $log_dir/cgfl.bash
}

get_locals(){
   local EXE=$1
   #func_list=$(/usr/bin/nm  $EXE | egrep -w '[tT]' | egrep -v '(__libc_csu|__x86.get_pc_thunk|\.L|__do_global|_init|_fini|_start|register_tm_clones)' | awk '{print $NF}' | sort -u) 
   #func_re=$(echo $func_list | perl -p -e'chomp($_);s/$/|/g;' | perl -p -e's/\|$//')
   init_re='__frame_dummy_init_array_entry|_init|__init_array_end|__init_array_start|__libc_csu_init|mutex_init'
   fini_re='__do_global_dtors_aux_fini_array_entry|_fini|__libc_csu_fini'
   thunk_re='__x86.get_pc_thunk.[abcds][ix]|__cxa_pure_virtual'
   reg_re='deregister_tm_clones|register_tm_clones'
   glob_re='__do_global_dtors_aux|__do_global_dtors_aux_fini_array_entry'
   start_re='_start|__init_array_start|start'
   alloc_re='((cgc_)?(allocate_buffer|allocate_new_blk|allocate_span|filter_alloc|large_alloc|malloc_free|malloc_huge|run_alloc|small_alloc|small_alloc_run|tiny_alloc))'
   L_re='\.L[[:digit:]]+'
   globals_re='((cgc__?)?(free|malloc|calloc|realloc|free|malloc_huge|allocate_new_blk|small_free|free_huge|memcpy|memset|memcmp|memchr|sprintf|snprintf|vsnprintf|vsprintf|vsfprintf|vprintf|vfprintf|fdprintf|printf|fflush|large_alloc|large_free|tiny_alloc|small_alloc|small_free|small_unlink_free|malloc_alloc|chunk_to_ptr|malloc_free|fread|ssmalloc|freaduntil|recvline|putc|recv|write|fwrite|memmove|coalesce|strcmp|strncmp|strchr|strnchr|strcat|bzero|itoa|atoi|atof|ftoa|strn?cpy|getc|strtol|strn?len|strsep|exit|is(alnum|alpha|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|xdigit)|to(ascii|lower|upper)|randint))'
   instr=""
   if [[ ! -z $MIN_INSTRS ]] ; then instr=" --instr-min $MIN_INSTRS "; fi
   minscreen_re=$($script_dir/screen_small_functions.py --json-in info.json --byte-min $MIN_BYTES $instr |  perl -p -e'chomp($_);s/$/|/g;' | perl -p -e's/\|$//')
   echo "minscreen_re=$minscreen_re"

   specific_issue_re='((cgc__?)(gb_new|gb_reset))'
#   globals_re='cgc_free|cgc_malloc|cgc_calloc|cgc_realloc|cgc_free|malloc_huge|cgc_ftoa|cgc_allocate_new_blk|allocate_new_blk|cgc_small_free|free_huge|cgc_memcmp|cgc_memchr|cgc_sprintf|cgc_snprintf|cgc_vsnprintf|cgc_vsprintf|cgc_large_alloc|cgc_large_free|cgc_memcpy|cgc_putc|cgc_vprintf|cgc__vsfprintf|cgc_printf|allocate_new_blk|cgc_memset|cgc_write|cgc_recv|cgc_tiny_alloc|small_alloc|small_free|small_unlink_free|cgc_tiny_alloc|cgc_malloc_alloc|cgc_chunk_to_ptr|malloc_free|cgc_fread|cgc__malloc|cgc_ssmalloc|cgc_fflush|cgc_freaduntil|cgc_fdprintf|cgc_recvline|cgc_fwrite|cgc_memmove|cgc_coalesce|cgc_atoi|cgc_strcmp|cgc_strncmp|cgc_strchr|cgc_strnchr|cgc_gb_new|cgc_gb_reset|cgc_strcat|cgc_bzero|cgc_itoa|cgc_atoi|cgc_strn?cpy|cgc__getc|cgc_vfprintf|cgc_strtol|cgc_strn?len|cgc_strsep|cgc_exit|cgc_is(alnum|alpha|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|xdigit)|cgc_to(ascii|lower|upper)'
   libfunc_re=$(/usr/bin/nm  $CGC_CB_DIR/build32/include/libcgc.so | /bin/egrep -w '[tT]' | awk '{print $NF}' | sort -u | perl -p -e'chomp($_);s/$/|/g;' | perl -p -e"s/$/$globals_re|$init_re|$fini_re|$thunk_re|$reg_re|$glob_re|$start_re|$alloc_re|$L_re|$specific_issue_re/")
   echo "func_re=\$(/usr/bin/nm  $EXE | /bin/egrep -w '[tT]' | egrep -w \"($minscreen_re)\" | egrep -vw \"($libfunc_re)\" | awk '{print \$NF}' | sort -u | perl -p -e'chomp(\$_);s/$/|/g;' | perl -p -e's/\\|\$//')"
   #func_re=$(/usr/bin/nm  $EXE | /bin/egrep -w '[tT]' | /bin/egrep -vw "($init_re|$fini_re|$thunk_re|$reg_re|$glob_re|$start_re|$alloc_re|$L_re|$libfunc_re)" | awk '{print $NF}' | sort -u | perl -p -e'chomp($_);s/$/|/g;' | perl -p -e's/\|$//')
   func_re=$(/usr/bin/nm  $EXE | /bin/egrep -w '[tT]' | /bin/egrep -w "($minscreen_re)" | /bin/egrep -vw "($libfunc_re)" | awk '{print $NF}' | sort -u | perl -p -e'chomp($_);s/$/|/g;' | perl -p -e's/\|$//')
   #func_re=$(/usr/bin/nm  $EXE | egrep -w '[tT]' | egrep -v '(__libc_csu|__x86.get_pc_thunk|\.L|__do_global|_init|_fini|_start|register_tm_clones)' | awk '{print $NF}' | sort -u | perl -p -e'chomp($_);s/$/|/g;' | perl -p -e's/\|$//')
   return $?
}


run_reg() {
   local EXE=$1
   local TEST=""
   local EXPECTING_NEG_TO_PASS=$2
   local num_runs=$3
   echo "Regression: $EXE"
   echo "CGFL Top Rank: $TOP_K"
   get_locals $EXE
   local FUNC_RE=$func_re
   local LIBFUNC_RE=$libfunc_re

   TESTLIST=()
   log_dir=$results_dir
   mkdir -p $log_dir
   [[ -e $log_dir/cgfl.bash ]] && rm $log_dir/cgfl.bash; 
   echo '#!/bin/bash' > $log_dir/cgfl.bash; chmod +x $log_dir/cgfl.bash
   if [ $EXPECTING_NEG_TO_PASS -eq 1 ] ; then
      echo "Expecting negative tests to PASS"
   else
      echo "Expecting negative tests to FAIL"
   fi
   # NEGATIVE TESTS 
   local k=0
   local negofail=0
   local neg=$(egrep 'neg\-tests' configuration-func-repair | awk '{print $NF}')
   for i in $(seq 1 $neg); do
      TEST="n$i"
      out=$($test_script $EXE $TEST ; echo $?) 
	  x=$(echo $out | awk '{print $NF}')
	  negotiation_fail=$(echo $out | perl -p -e's/^.*\(\-?\d+,\s+\-?\d+,\s+(True|False)\).*$/$1/')
      outsize=$(du $reg_log_subdir/$TEST.cgfl.out | awk '{print $1}')
      if (( $outsize == 0 )) ; then 
         lEXE="${EXE}_patched"
         if [[ "$EXE" == *"_patched" ]]; then
            lEXE=$(echo $EXE | sed 's/_patched//')
         fi
         if [[ ! -e $lEXE ]]; then 
            echo "ERROR: $TEST.cgfl.out is empty [$EXE] and $lEXE doesn't exist"
         else
             iter=0
             while (( $outsize == 0 )); do
                (( iter+=1 ))
                out=$($test_script $lEXE $TEST ; echo $?) 
                x=$(echo $out | awk '{print $NF}')
   	            negotiation_fail=$(echo $out | perl -p -e's/^.*\(\-?\d+,\s+\-?\d+,\s+(True|False)\).*$/$1/')
                outsize=$(du $reg_log_subdir/$TEST.cgfl.out | awk '{print $1}')
                if (( $outsize == 0 )); then 
                   echo "ERROR: $TEST.cgfl.out is empty for both $lEXE and $EXE"
                   if (( $iter > 4 )); then
                      break
                   fi
                else
                   break
                fi
             done
         fi
      fi
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
      id=$(ls $log_dir/$TEST.cg.out.* 2> /dev/null | wc -l)
      if [[ -e $log_dir/$TEST.cg.log ]]; then 
      mv $log_dir/$TEST.cg.log $log_dir/$TEST.cg.log.$id
      fi
      if [[ -e $log_dir/$TEST.cg.out ]]; then 
      mv $log_dir/$TEST.cg.out $log_dir/$TEST.cg.out.$id
      fi
      cp $reg_log_subdir/$TEST.cgfl.log $log_dir/$TEST.cg.log
      cp $reg_log_subdir/$TEST.cgfl.out $log_dir/$TEST.cg.out
      TESTLIST+=($TEST)
      #cg_annotate $EXE $log_dir $TEST $FUNC_RE $LIBFUNC_RE
      #generate_all_dict $log_dir
   done
   # POSITIVE TESTS 
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
      id=$(ls $log_dir/$TEST.cg.out.* 2> /dev/null | wc -l)
      if [[ -e $log_dir/$TEST.cg.log ]]; then 
      mv $log_dir/$TEST.cg.log $log_dir/$TEST.cg.log.$id
      fi
      if [[ -e $log_dir/$TEST.cg.out ]]; then 
      mv $log_dir/$TEST.cg.out $log_dir/$TEST.cg.out.$id
      fi
      cp $reg_log_subdir/$TEST.cgfl.log $log_dir/$TEST.cg.log
      cp $reg_log_subdir/$TEST.cgfl.out $log_dir/$TEST.cg.out
      TESTLIST+=($TEST)
      #cg_annotate $EXE $log_dir $TEST $FUNC_RE $LIBFUNC_RE
      #generate_all_dict $log_dir
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
   if (( $pos == 0 )) || (( $neg == 0 )); then 
      echo "WARNING!!!! No available tests! [pos: $pos] [neg: $neg]"
      return $ret
   fi
   for TEST in ${TESTLIST[*]}; do 
      cg_annotate $EXE $log_dir $TEST $FUNC_RE $LIBFUNC_RE
   done
   generate_all_dict $log_dir
   echo "$script_dir/calc_susp_pp.py --ext \".dict\" --in \"$log_dir\" --out $outdir --all_rank --pickle --standardize --print --r_input --r-out $r_dir --cb $EXE --top-k-percent $TOP_K --log susp-fn.log > $log_dir/$EXE.calc_susp_pp.log  2> $log_dir/$EXE.rscript.log" >> $log_dir/cgfl.bash
   $script_dir/calc_susp_pp.py --ext ".dict" --in "$log_dir" --out $outdir --all_rank --pickle --standardize --print --r_input --r-out $r_dir --cb $EXE --top-k-percent $TOP_K --log susp-fn.log > $log_dir/$EXE.calc_susp_pp.log 2> $log_dir/$EXE.rscript.log
   return $ret
}


if [[ -z $TEST ]]; then
#Usage[1]: ./sanity.bash <executable>
   # not expecting negative tests to pass

   run_reg "$EXE" "0" $num_runs;
   
elif (( $regression == 1 )) ; then 
#Usage[1]: ./sanity.bash <executable> -regression
   # not expecting negative tests to pass
   run_reg "$EXE" "0" $num_runs;
   stat1=$ret
   patch="${EXE}_patched"
   # expecting negative tests to pass with _patched 
   run_reg "$patch" "1" $num_runs;
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
#Usage[2]: ./sanity_perf.bash <executable> <test> [num test runs (default:10)]
echo "Testing $EXE $TEST";
NUM=$3;
if [[ -z $NUM ]]; then
NUM=10
fi

DEBUG=$4;
j=0;

get_locals $EXE
local FUNC_RE=$func_re
local LIBFUNC_RE=$libfunc_re

log_dir=$results_dir
mkdir -p $log_dir

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
id=$(ls $log_dir/$TEST.cg.out.* 2> /dev/null | wc -l)
if [[ -e $log_dir/$TEST.cg.log ]]; then 
mv $log_dir/$TEST.cg.log $log_dir/$TEST.cg.log.$id
fi
if [[ -e $log_dir/$TEST.cg.out ]]; then 
mv $log_dir/$TEST.cg.out $log_dir/$TEST.cg.out.$id
fi
cp $reg_log_subdir/$TEST.cgfl.log $log_dir/$TEST.cg.log
cp $reg_log_subdir/$TEST.cgfl.out $log_dir/$TEST.cg.out
done;
echo "# of failed $TEST tests $j of $i"
cg_annotate $EXE $log_dir $TEST $FUNC_RE $LIBFUNC_RE
generate_all_dict $log_dir
fi
