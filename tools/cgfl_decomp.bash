#!/bin/bash 

PROGRAM_BASE_DIR=$1
mysrcdir=$PROGRAM_BASE_DIR
bin=$(basename -- $mysrcdir)
BASE_DIR=$(dirname -- $PROGRAM_BASE_DIR)

mydestdir=$2
echo "DESTINATION $mydestdir"
MYBYTES=$4


TOOL_DIR=$PRD_BASE_DIR/tools
TEMPLATES_DIR=$TOOL_DIR/templates

DECOMP_TOOL_DIR=$PART_DECOMP_DIR
MYCC=gcc
MYCPP=g++

TOP_K_PERCENT=0.35
# (52 - 3) / 7 = 7 stack pushes
MIN_BYTES_FN=$MYBYTES;
if [[ -z $MYBYTES ]] ; then 
   MIN_BYTES_FN=52
fi
MIN_INSTRS_FN=

EXECUTE=( 1 1 )
RESET=( 0 0 )

# BinREPARED destination variables
if [[ -z $mydestdir ]]; then
  mydestdir=$BASE_DIR/prd_e2e
else
  mydestdir=$(realpath $mydestdir)
fi
destdir=$mydestdir
dest=$(basename $destdir)

# variables for stages of BinREPARED
srcdir="$destdir/bins"
builddir="$destdir/build"
cgfldir="$destdir/cgfl"
decompdir="$destdir/decomp"
#perfdir="$destdir/perf_log"
stage_info_dir="$destdir/status"
aprdir="$destdir/apr"
prophetexe="$PROPHET64_BASE/src/prophet"

status_log="$stage_info_dir/$bin.log"
apr_regression="$destdir/apr/scripts/APR.regression.bash"
apr_gp_reg="$destdir/apr/scripts/APR.gp_reg.bash"
apr_p_reg="$destdir/apr/scripts/APR.p_reg.bash"

if (( ${RESET[0]} == 1 )); then 
[[ -e $status_log ]] && rm $status_log 
fi
mkdir -p $stage_info_dir && touch $status_log


##########################################################################
# 1. Setup for CB
bin_src="$srcdir/$bin"
bin_build="$builddir/$bin"
   
if (( ${EXECUTE[0]} == 1 )); then 
    echo "Executing BUILD stage"
    echo "-----------------------"

    [[ ! -e $srcdir ]] && mkdir -p $srcdir
    [[ ! -e $bin_src ]] && cp -r $mysrcdir $bin_src
    [[ ! -e $bin_build/Makefile.prd ]] && ln -sf $TEMPLATES_DIR/Makefile.prd $bin_build/
    if [[ ! -e $bin_build/polls  && -e $BASE_DIR/polls/$bin/poller ]] ; then 
        ln -sf $BASE_DIR/polls/$bin/poller $bin_build/
    elif [[ ! -e $bin_build/polls ]]; then
        ln -sf $BASE_DIR/challenges/$bin/poller $bin_build/
    fi
    if [[ ! -e $bin_build/test.sh ]]; then
     x=$(wc -l $BASE_DIR/cgc_test/$bin/test.sh | awk '{print $1}')
     head -n 1 $BASE_DIR/cgc_test/$bin/test.sh >> $bin_build/test.sh
     echo "export LD_BIND_NOW=1" >> $bin_build/test.sh
     tail -n $(( $x-1 )) $BASE_DIR/cgc_test/$bin/test.sh >> $bin_build/test.sh
     chmod +x $bin_build/test.sh
    fi
    [[ ! -e $bin_build/configuration-func-repair ]] && ln -sf $BASE_DIR/cgc_test/$bin/configuration-func-repair $bin_build/
    [[ ! -e $bin_build/tools ]] && ln -sf $CGC_TOOL_DIR $bin_build/tools
   
    [[ -e $bin_build/$bin ]] && echo "original binary build : SUCCESS" >> $status_log
    [[ ! -e $bin_build/$bin ]] && echo "original binary build : FAIL" >> $status_log && exit -1

    pushd $bin_build > /dev/null
    echo "--------------------------------"
    echo "Running sanity tests on $bin image"
    sanity_log="sanity.$bin.log"
    $TOOL_DIR/sanity.bash $bin -fail-fast |& tee $sanity_log
    retval=$?
    FAILED=$(tail -n 1 $sanity_log | egrep -c 'EXITING EARLY');
    if (( $FAILED==1 )); then
        echo "CB sanity check [early fail] : FAIL" >> $status_log && exit -1
    fi
    pos=$(tail -n 10 $sanity_log | egrep ' failed POSITIVE tests');
    neg=$(tail -n 10 $sanity_log | egrep ' failed NEGATIVE tests');
    negofail=$(tail -n 10 $sanity_log | egrep 'negotiation_failed NEGATIVE tests');
    pf=$(echo $pos | awk '{print $6}');
    pa=$(echo $pos | awk '{print $NF}');
    nf=$(echo $neg | awk '{print $6}');
    na=$(echo $neg | awk '{print $NF}');
    negof=$(echo $negofail | awk '{print $6}');
    negoa=$(echo $negofail | awk '{print $NF}');
    if (( $pa == 0 )); then 
        echo "CB sanity check [ZERO POSITIVE TESTS] : FAIL" >> $status_log && exit -1
    fi;
    if (( $na == 0 )); then 
        echo "CB sanity check [ZERO NEGATIVE TESTS] : FAIL" >> $status_log && exit -1
    fi;
    if (( $na != $nf )); then
        echo "CB sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] - NEGATIVE TEST ISSUE : FAIL" >> $status_log && exit -1
    elif (( $pf != 0 )); then
        echo "CB sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] - POSITIVE TEST ISSUE : FAIL" >> $status_log && exit -1
    else 
        echo "CB sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : SUCCESS" >> $status_log
    fi;
    popd > /dev/null

    echo "$TOOL_DIR/screen_small_functions.py --exe $bin_build/$bin --json-out $bin_build/info.json"
    $TOOL_DIR/screen_small_functions.py --exe $bin_build/$bin --json-out $bin_build/info.json


fi

##########################################################################
# 2. CGFL for CB => buggy function set

 # local CGFL stage variable
 profile_out=$cgfldir/cgfl_profile/$bin  # raw profile data from test runs
 processed_out=$cgfldir/cgfl_results/$bin  # processed profile data (annotated and dict)
 r_out=$cgfldir/r_scripts                       # Rscript directory
 ranked_out=$cgfldir/cgfl_rank/$bin  # R's RankAggreg output

if (( ${EXECUTE[1]} == 1 )); then 
    echo "Executing CGFL stage"
    echo "-----------------------"
    if (( ${RESET[1]} > 0 )) ; then
        echo "Reseting CGFL substages >= ${RESET[1]}"
        (( ${RESET[1]} >= 1 )) && [[ -e $profile_out ]]  && rm -rf $profile_out
        (( ${RESET[1]} >= 2 )) && [[ -e $processed_out ]]  && rm -rf $processed_out
        (( ${RESET[1]} >= 3 )) && [[ -e $r_out/$bin.r ]]  && rm -f $r_out/$bin.r
        (( ${RESET[1]} >= 4 )) && [[ -e $ranked_out/$bin.top_rank.list ]]  && rm $ranked_out/$bin.top_rank.list
    fi
    if [[ ! -e $bin_build/info.json ]]; then 
    echo "$TOOL_DIR/screen_small_functions.py --exe $bin_build/$bin --json-out $bin_build/info.json"
    $TOOL_DIR/screen_small_functions.py --exe $bin_build/$bin --json-out $bin_build/info.json
    fi
   
   
    if [[ ! -e $profile_out ]] ; then 
        $TOOL_DIR/convert_test_to_cgfl.bash $bin --src=$builddir --logdir=$profile_out
        #ln -sf $CGC_CB_DIR/genprog/$bin/test_cgfl.sh build32/challenges/$bin/ ;
        pushd $bin_build > /dev/null;
        instr=""
        if [[ ! -z $MIN_INSTRS_FN ]]; then
             instr=" --min-instrs $MIN_INSTRS_FN"
        fi
        echo "$TOOL_DIR/sanity_cgfl.bash $bin --profile-out=$profile_out \
                  --r-out=$r_out --results=$processed_out --top-k-percent=$TOP_K_PERCENT \
                  --min-bytes $MIN_BYTES_FN $instr |& tee sanity_cgfl.log;"
        $TOOL_DIR/sanity_cgfl.bash $bin --profile-out=$profile_out \
                  --r-out=$r_out --results=$processed_out --top-k-percent=$TOP_K_PERCENT \
                  --min-bytes $MIN_BYTES_FN $instr |& tee sanity_cgfl.log;
        popd > /dev/null
    fi
    if [[ ! -e $r_out/$bin.r  ]] ; then 
        #echo "Processing CGFL with $TOP_K_PERCENT as rank"
        #$TOOL_DIR/prdtools/calc_susp_pp.py --ext ".dict" --in "$processed_out" --out $bin_build --all_rank \
        #  --pickle --standardize --print --r_input --r-out $r_out \
        #  --cb $bin --top-k-percent $TOP_K_PERCENT > $processed_out/$bin.calc_susp_pp.log 2> $processed_out/$bin.rscript.log
        instr=""
        if [[ ! -z $SEED ]]; then
             instr+=" --r-seed $SEED "
        fi
        if [[ ! -z $MIN_INSTRS_FN ]]; then
             instr+=" --instr-min $MIN_INSTRS_FN"
        fi
        echo "$TOOL_DIR/prdtools/cgfl.py --top-k-percent $TOP_K_PERCENT --r-out $r_out --exe $bin_build/$bin \
        --lib $bin_build/build/include/libcgc.so \
        --src $BASE_DIR/challenges/$bin/src \
        --results $processed_out \
        --byte-min $MIN_BYTES_FN \
        $instr"

        $TOOL_DIR/prdtools/cgfl.py --top-k-percent $TOP_K_PERCENT --r-out $r_out --exe $bin_build/$bin \
        --lib $bin_build/$bin/build/include/libcgc.so \
        --src $BASE_DIR/challenges/$bin/src \
        --results $processed_out \
        --byte-min $MIN_BYTES_FN \
        $instr

    fi
    if [[ ! -e $r_out/$bin.r  ]] ; then 
        echo "cgfl top rank [callgrind test issue] : FAIL" >> $status_log; exit -1; 
    fi

    fsize=$(file $bin.top_rank.list | awk '{print $NF}') 
    if [[ ! -e $ranked_out/$bin.top_rank.list || $fsize == "empty" ]] ; then 
        mkdir -p $ranked_out
        pushd $ranked_out > /dev/null
        $r_out/$bin.r |& tee $bin.cgfl.log
        cat $bin.$TOP_K_PERCENT.seed_${SEED}.results.log | sed 's/ /:/g' > $bin.top_rank.list
        fsize=$(file $bin.top_rank.list | awk '{print $NF}') 
        popd > /dev/null
    fi
    if [[ ! -e $ranked_out/$bin.top_rank.list ]]; then
    fsize="empty"
    else
    fsize=$(file $ranked_out/$bin.top_rank.list | awk '{print $NF}') 
    fi
    $TOOL_DIR/cgfl_status_pp.bash $destdir $bin $SEED
    if [[ -e $ranked_out/$bin.top_rank.list && $fsize != "empty" ]] ; then 
        echo "cgfl top rank : SUCCESS" >> $status_log ; 
    else 
        echo "cgfl top rank [ R issue ] : FAIL" >> $status_log; exit -1
    fi

fi
##########################################################################
# 3. Decompilation of CB for buggy function set => decomp source code
decomp_in=$decompdir/decomp_in
decomp_out=$decompdir/decomp_out
decomp_test=$decompdir/test/$bin

if (( ${EXECUTE[2]} == 1 )); then 
    if [[ ! -e $ranked_out/$bin.top_rank.list ]]; then
    echo "ERROR: decompilation error - missing $bin CGFL rank info"
    exit -1
    fi
    echo "Executing DECOMP stage"
    echo "-----------------------"
    (( ${RESET[2]} >= 0 )) && echo "Reseting DECOMP substage >= ${RESET[2]}" && rm -rf $decomp_test $decomp_in/$bin $decomp_out/$bin
    if [[ -e $decomp_in/$bin.target_list  ]]; then 
        echo "decompilation previously run for $bin"
    elif [[ ! -e $decomp_in/$bin.target_list  ]]; then 
        mkdir -p $decomp_in $decomp_out $decomp_test
    
       # note $decomp_out/$bin is generated by decompilation script
        buggy_set=$(/bin/cat $ranked_out/$bin.top_rank.list | perl -p -e's/(?<!:):(?!:)/ /g')
        i=0
        valid=""
        for f in ${buggy_set[*]}; do
            echo "Decompiling $f"
            din="$decomp_test/in"
            dout="$decomp_test/out.$i"
            mkdir -p $din $dout
            $TOOL_DIR/decompile.py -p $bin_build/$bin --target-list $din/$bin.$i.target_list \
            -l $dout/multidecomp.log -o $dout -s $DECOMP_TOOL_DIR -f $f
            #echo -n "$bin,$bin_build/$bin,$f" > $din/$bin.$i.target_list
            #python3 $DECOMP_TOOL_DIR/prd_multidecomp_ida.py --target_list \
            #$din/$bin.$i.target_list --ouput_directory $dout \
            #--scriptpath $DECOMP_TOOL_DIR/get_ida_details.py |& tee $dout/multidecomp.log
            #echo "====DONE====" >> $dout/multidecomp.log
            (( i+=1 ))
            [[ ! -e $dout/$bin ]] && echo "decompilation [Decompilation] $f : FAIL" >> $status_log && continue
            cp -v $TEMPLATES_DIR/Makefile.prd $dout/$bin/
            cp -v $TEMPLATES_DIR/script.ld $dout/$bin/
            cp -v $dout/$bin/${bin}_recomp.c $dout/$bin/${bin}_recomp.c.orig 
            ln -sf $bin_build/test.sh $dout/$bin/
            ln -sf $bin_build/configuration-func-repair $dout/$bin/
            ln -sf $bin_build/poller $dout/$bin/
            ln -sf $bin_build/tools $dout/$bin/
            ln -sf $bin_build/$bin $dout/$bin/
            
            for j in $(ls $bin_build/pov*.pov); do 
            ln -sf $j $dout/$bin/
            done
            pushd $dout/$bin > /dev/null
            make -f Makefile.prd clean hook |& tee make.decomp_hook.log
            [[ ! -e libhook.so ]] && echo "decompilation [Recompilation] $f : FAILED" >> $status_log && popd > /dev/null &&  continue
            x=$(egrep -c 'Error\! Unbound functions\!' make.decomp_hook.log)
            (( $x>0 )) && echo "decompilation [Recompilation Symbol Binding] $f : FAILED" >> $status_log && popd > /dev/null &&  continue
            $TOOL_DIR/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${bin}_recomp.c
            diff --brief ${bin}_recomp.c ${bin}_recomp.c.orig &> /dev/null ; diff_ret=$?
            (( $?!=0 )) && echo "decompilation [Inline ASM Insertion] $f : FAIL" >> $status_log && exit -1
            [[ -e $bin.trampoline.bin ]] && rm $bin.trampoline.bin
            make -n -f  Makefile.prd clean hook funcinsert
            make -f Makefile.prd clean hook funcinsert |& tee make.prd_build.log
            [[ ! -e $bin.trampoline.bin ]] && echo "decompilation [PRD Binary] $f : FAIL" >> $status_log && popd > /dev/null && continue
            sanity_log="sanity.trampoline.log"
            echo "--------------------------------"
            echo "Running sanity tests on $f image"
            $TOOL_DIR/sanity.bash $bin.trampoline.bin -fail-fast |& tee $sanity_log
            retval=$?
            FAILED=$(tail -n 1 $sanity_log | egrep -c 'EXITING EARLY');
            if (( $FAILED==1 )); then
                echo "PRD [$f] sanity check [early fail] : FAIL" >> $status_log && popd > /dev/null && continue
            fi
            pos=$(tail -n 10 $sanity_log | egrep ' failed POSITIVE tests');
            neg=$(tail -n 10 $sanity_log | egrep ' failed NEGATIVE tests');
            negofail=$(tail -n 10 $sanity_log | egrep 'negotiation_failed NEGATIVE tests');
            pf=$(echo $pos | awk '{print $6}');
            pa=$(echo $pos | awk '{print $NF}');
            nf=$(echo $neg | awk '{print $6}');
            na=$(echo $neg | awk '{print $NF}');
            negof=$(echo $negofail | awk '{print $6}');
            negoa=$(echo $negofail | awk '{print $NF}');
            if (( $na != $nf )); then
                echo "PRD [$f] sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : FAIL" >> $status_log && popd > /dev/null && continue
            elif (( $pf != 0 )); then
                echo "PRD [$f] sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : FAIL" >> $status_log && popd > /dev/null && continue
            else 
                echo "PRD [$f] sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : SUCCESS" >> $status_log
            fi;
    
            if [[ $valid != "" ]]; then valid+=":"; fi
            echo "Valid : $f"
            valid+="$f"
            popd > /dev/null
        done
        echo "Valid decompiled functions: $valid"
        
        [[ $valid == "" ]] && echo "decompilation [No valid decompiled functions] : FAIL" >> $status_log && exit -1
        # generate input to decompilation script
        (echo -n "$bin,$bin_build/$bin,$valid") > $decomp_in/$bin.target_list
       
    fi

    if [[ ! -e $decomp_out/$bin ]]; then 
       $TOOL_DIR/decompile.py -p $bin_build/$bin --target-list $decomp_in/$bin.target_list \
            -l $decomp_out/multidecomp.$bin.log -o $decomp_out -s $DECOMP_TOOL_DIR -f DUMMY
       #python3 $DECOMP_TOOL_DIR/prd_multidecomp_ida.py --target_list \
       # $decomp_in/$bin.target_list --ouput_directory $decomp_out \
       # --scriptpath $DECOMP_TOOL_DIR/get_ida_details.py |& tee $decomp_out/multidecomp.$bin.log
        mv $decomp_out/multidecomp.$bin.log $decomp_out/$bin/multidecomp.log
    fi 
    [[ ! -e $decomp_out/$bin ]] && echo "decompilation [Decompilation] : FAIL" >> $status_log && exit -1
    cp $TEMPLATES_DIR/Makefile.prd $decomp_out/$bin/
    cp $TEMPLATES_DIR/script.ld $decomp_out/$bin/
    ln -sf $bin_build/$bin $decomp_out/$bin/
    [[ ! -e $decomp_out/$bin/${bin}_recomp.c.orig ]] && cp $decomp_out/$bin/${bin}_recomp.c $decomp_out/$bin/${bin}_recomp.c.orig 

    pushd $decomp_out/$bin > /dev/null
        make -f Makefile.prd clean hook |& tee make.decomp_hook.log
        if [[ ! -e libhook.so ]]; then
           echo "Decompiled content failed to recompile for $bin!"
           echo "Exiting..."
           echo "decompilation [Recompilation] : FAIL" >> $status_log
           exit -1
        fi
        x=$(egrep -c 'Error\! Unbound functions\!' make.decomp_hook.log)
        (( $x>0 )) && echo "decompilation [Recompilation Symbol Binding] : FAILED" >> $status_log && exit -1
        $BASE_DIR/genprog_ida/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${bin}_recomp.c
        diff --brief ${bin}_recomp.c ${bin}_recomp.c.orig &> /dev/null ; diff_ret=$?
        (( $?!=0 )) && echo "decompilation [Inline ASM Insertion] $f : FAIL" >> $status_log && exit -1
        [[ -e $bin.trampoline.bin ]] && rm $bin.trampoline.bin
        make -n -f  Makefile.prd clean hook funcinsert
        make -f Makefile.prd clean hook funcinsert |& tee make.prd_build.log
    
    popd > /dev/null

    [[ ! -e $decomp_out/$bin/$bin.trampoline.bin ]] && echo "decompilation : FAIL" >> $status_log && exit -1
    [[ -e $decomp_out/$bin/$bin.trampoline.bin ]] && echo "decompilation : SUCCESS" >> $status_log 

fi
