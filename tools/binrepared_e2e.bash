#!/bin/bash 

cb=$1
mydestdir=$2
echo "DESTINATION $mydestdir"
MYBYTES=$3
SEED=$4

REQUIRE_NEG_TESTS_TO_FAIL=1

GROUND_TRUTH=$(dirname -- $(realpath -- $mydestdir))
echo "GROUND_TRUTH: $GROUND_TRUTH"
# Let's grab and unpack the Ground Truth for the CGC dataset
if [[ ! -d $GROUND_TRUTH/patched_functions ]]; then
  patched_tgz="$PRD_BASE_DIR/tools/cb-multios/patched_functions.tgz"
  echo "Obtaining CGC Ground Truth from $patched_tgz"
  tar -xvzf $patched_tgz $GROUND_TRUTH/
fi

# 0 : setup
# 1 : CGFL
# 2 : DECOMPILATION
# 3 : VERIFY PRD IMAGE
# 4 : PERFORMANCE
# 5 : APR

#EXECUTE=( 1 1 1 1 1 1 )
EXECUTE=( 1 1 1 1 0 1 )
RESET=( 0 0 0 0 0 0 )

BASE_DIR=$CGC_CB_DIR
CGC_BASE_DIR=$CGC_CB_DIR
#TOOL_DIR=$CGC_CB_DIR
TOOL_DIR=$PRD_BASE_DIR/tools
TEMPLATES_DIR=$TOOL_DIR/templates

CGC_TOOL_DIR=$CGC_CB_DIR/tools #/python3 #moved from tools/python3 to tools
DECOMP_TOOL_DIR=$PART_DECOMP_DIR
MYCC=gcc-8
MYCPP=g++-8

TOP_K_PERCENT=0.35
# (52 - 3) / 7 = 7 stack pushes
MIN_BYTES_FN=$MYBYTES;
if [[ -z $MYBYTES ]] ; then 
   MIN_BYTES_FN=52
fi
MIN_INSTRS_FN=


# BinREPARED destination variables
if [[ -z $mydestdir ]]; then
  mydestdir=$BASE_DIR/prd_e2e
else
  mydestdir=$(realpath $mydestdir)
fi
destdir=$mydestdir
dest=$(basename $destdir)

# variables for stages of BinREPARED
srcdir="$destdir/cgc_cbs"
builddir="$destdir/build"
cgfldir="$destdir/cgfl"
decompdir="$destdir/decomp"
perfdir="$destdir/perf_log"
stage_info_dir="$destdir/status"
aprdir="$destdir/apr"
prophetexe="$PROPHET64_BASE/src/prophet"

status_log="$stage_info_dir/$cb.log"
apr_regression="$destdir/apr/scripts/APR.regression.bash"
apr_gp_reg="$destdir/apr/scripts/APR.gp_reg.bash"
apr_p_reg="$destdir/apr/scripts/APR.p_reg.bash"

if (( ${RESET[0]} == 1 )); then 
[[ -e $status_log ]] && rm $status_log 
fi
mkdir -p $stage_info_dir && touch $status_log


cd $CGC_BASE_DIR
##########################################################################
# 1. Setup for CB
cb_src="$srcdir/$cb"
cb_build="$builddir/$cb"
   
if (( ${EXECUTE[0]} == 1 )); then 
    echo "Executing BUILD stage"
    echo "-----------------------"

    $TOOL_DIR/cgc_test_setup.bash -v $cb ; 
   
    (( ${RESET[0]} != 0 )) && [[ -e $cb_src ]]  && rm -rf $cb_src $cb_build
   
    [[ ! -e $srcdir ]] && mkdir -p $srcdir
    [[ ! -e $srcdir/include ]] && cp -r $BASE_DIR/include $srcdir/
    [[ ! -e $srcdir/CMakeLists.txt ]] && cp $TEMPLATES_DIR/CMakeLists.txt $srcdir/
    [[ ! -e $srcdir/$cb ]] && cp -v -r $BASE_DIR/challenges/$cb $srcdir/
    if [[ ! -e $cb_build/$cb  || ! -e $cb_build/build ]] ; then
        mkdir -v -p $cb_build/build
        pushd $cb_build/build > /dev/null
        echo -e "pushd $cb_build/build > /dev/null \
        cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=$MYCC \
        -DCMAKE_ASM_COMPILER=$MYCC -DCMAKE_CXX_COMPILER=$MYCPP -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF \
        -DBINARY=$cb $srcdir"
        cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=$MYCC \
        -DCMAKE_ASM_COMPILER=$MYCC -DCMAKE_CXX_COMPILER=$MYCPP -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF \
        -DBINARY=$cb $srcdir
        cmake --build .
        popd > /dev/null
    fi
   
    [[ ! -e $cb_build/Makefile.prd ]] && ln -sf $TEMPLATES_DIR/Makefile.prd $cb_build/
    if [[ ! -e $cb_build/polls  && -e $BASE_DIR/polls/$cb/poller ]] ; then 
        ln -sf $BASE_DIR/polls/$cb/poller $cb_build/
    elif [[ ! -e $cb_build/polls ]]; then
        ln -sf $BASE_DIR/challenges/$cb/poller $cb_build/
    fi
    if [[ ! -e $cb_build/test.sh ]]; then
     x=$(wc -l $BASE_DIR/cgc_test/$cb/test.sh | awk '{print $1}')
     head -n 1 $BASE_DIR/cgc_test/$cb/test.sh >> $cb_build/test.sh
     echo "export LD_BIND_NOW=1" >> $cb_build/test.sh
     tail -n $(( $x-1 )) $BASE_DIR/cgc_test/$cb/test.sh >> $cb_build/test.sh
     chmod +x $cb_build/test.sh
    fi
    [[ ! -e $cb_build/configuration-func-repair ]] && ln -sf $BASE_DIR/cgc_test/$cb/configuration-func-repair $cb_build/
    [[ ! -e $cb_build/tools ]] && ln -sf $CGC_TOOL_DIR $cb_build/tools
   
    [[ -e $cb_build/$cb ]] && echo "original binary build : SUCCESS" >> $status_log
    [[ ! -e $cb_build/$cb ]] && echo "original binary build : FAIL" >> $status_log && exit -1

    
    pushd $cb_build > /dev/null
    echo "--------------------------------"
    sanity_log="sanity.$cb.log"
    if [[ ! -e $sanity_log ]] || (( $(tail -n 10 $sanity_log | egrep -c '(EXITING EARLY|failed POSITIVE|failed NEGATIVE)')==0 )); then
        echo "Running sanity tests on $cb image"
        $TOOL_DIR/sanity.bash $cb -fail-fast |& tee $sanity_log
        retval=$?
    else 
        echo "Collecting sanity results on $cb image"
    fi
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

    echo "$TOOL_DIR/screen_small_functions.py --exe $cb_build/$cb --json-out $cb_build/info.json"
    $TOOL_DIR/screen_small_functions.py --exe $cb_build/$cb --json-out $cb_build/info.json

fi

##########################################################################
# 2. CGFL for CB => buggy function set

 # local CGFL stage variable
 profile_out=$cgfldir/cgfl_profile/$cb  # raw profile data from test runs
 processed_out=$cgfldir/cgfl_results/$cb  # processed profile data (annotated and dict)
 r_out=$cgfldir/r_scripts                       # Rscript directory
 ranked_out=$cgfldir/cgfl_rank/$cb  # R's RankAggreg output

if (( ${EXECUTE[1]} == 1 )); then 
    echo "Executing CGFL stage"
    echo "-----------------------"
    if (( ${RESET[1]} > 0 )) ; then
        echo "Reseting CGFL substages >= ${RESET[1]}"
        (( ${RESET[1]} >= 1 )) && [[ -e $profile_out ]]  && rm -rf $profile_out
        (( ${RESET[1]} >= 2 )) && [[ -e $processed_out ]]  && rm -rf $processed_out
        (( ${RESET[1]} >= 3 )) && [[ -e $r_out/$cb.r ]]  && rm -f $r_out/$cb.r
        (( ${RESET[1]} >= 4 )) && [[ -e $ranked_out/$cb.top_rank.list ]]  && rm $ranked_out/$cb.top_rank.list
    fi
    if [[ ! -e $cb_build/info.json ]]; then 
    echo "$TOOL_DIR/screen_small_functions.py --exe $cb_build/$cb --json-out $cb_build/info.json"
    $TOOL_DIR/screen_small_functions.py --exe $cb_build/$cb --json-out $cb_build/info.json
    fi
   
    echo "Checking if CGFL output exists : $profile_out"
    if [[ ! -e $profile_out ]] ; then 
        $TOOL_DIR/convert_test_to_cgfl.bash $cb --src=$builddir --logdir=$profile_out
        #ln -sf $CGC_CB_DIR/genprog/$cb/test_cgfl.sh build32/challenges/$cb/ ;
        pushd $cb_build > /dev/null;
        instr=""
        if [[ ! -z $MIN_INSTRS_FN ]]; then
             instr=" --min-instrs $MIN_INSTRS_FN"
        fi
        echo "$TOOL_DIR/sanity_cgfl.bash $cb --profile-out=$profile_out \
                  --r-out=$r_out --results=$processed_out --top-k-percent=$TOP_K_PERCENT \
                  --min-bytes $MIN_BYTES_FN $instr |& tee sanity_cgfl.log;"
        $TOOL_DIR/sanity_cgfl.bash $cb --profile-out=$profile_out \
                  --r-out=$r_out --results=$processed_out --top-k-percent=$TOP_K_PERCENT \
                  --min-bytes $MIN_BYTES_FN $instr |& tee sanity_cgfl.log;
        popd > /dev/null
    fi
    if [[ ! -e $r_out/$cb.r  ]] ; then 
        #echo "Processing CGFL with $TOP_K_PERCENT as rank"
        #$TOOL_DIR/prdtools/calc_susp_pp.py --ext ".dict" --in "$processed_out" --out $cb_build --all_rank \
        #  --pickle --standardize --print --r_input --r-out $r_out \
        #  --cb $cb --top-k-percent $TOP_K_PERCENT > $processed_out/$cb.calc_susp_pp.log 2> $processed_out/$cb.rscript.log
        instr=""
        if [[ ! -z $SEED ]]; then
             instr+=" --r-seed $SEED "
        fi
        if [[ ! -z $MIN_INSTRS_FN ]]; then
             instr+=" --instr-min $MIN_INSTRS_FN"
        fi
        echo "$TOOL_DIR/prdtools/cgfl.py --top-k-percent $TOP_K_PERCENT --r-out $r_out --exe $cb_build/$cb \
        --lib $cb_build/build/include/libcgc.so \
        --src $BASE_DIR/challenges/$cb/src \
        --results $processed_out \
        --byte-min $MIN_BYTES_FN \
        $instr"

        $TOOL_DIR/prdtools/cgfl.py --top-k-percent $TOP_K_PERCENT --r-out $r_out --exe $cb_build/$cb \
        --lib $cb_build/$cb/build/include/libcgc.so \
        --src $BASE_DIR/challenges/$cb/src \
        --results $processed_out \
        --byte-min $MIN_BYTES_FN \
        $instr

    fi
    if [[ ! -e $r_out/$cb.r  ]] ; then 
        echo "cgfl top rank [callgrind test issue] : FAIL" >> $status_log; exit -1; 
    fi
    fsize="empty"
    if [[ -e $ranked_out/$cb.top_rank.list ]]; then
        fsize=$(file $ranked_out/$cb.top_rank.list | awk '{print $NF}') 
    fi
    echo "$ranked_out/$cb.top_rank.list : file size = $fsize"
    if [[ $fsize == "empty" ]] ; then 
        mkdir -p $ranked_out
        pushd $ranked_out > /dev/null
        $r_out/$cb.r |& tee $cb.cgfl.log
        cat $cb.$TOP_K_PERCENT.seed_${SEED}.results.log | sed 's/ /:/g' > $cb.top_rank.list
        fsize=$(file $cb.top_rank.list | awk '{print $NF}') 
        for x in $(ls $r_out/$cb-*.r); do
            id_=$(echo $x | perl -p -e"s#.*/([^/]*).r\$#\$1#;s#$cb##")
            $x |& tee $cb$id_.cgfl.log
            cat $cb$id_.$TOP_K_PERCENT.seed_${SEED}.results.log | sed 's/ /:/g' > $cb$id_.top_rank.list
        done
        popd > /dev/null
    fi
    if [[ ! -e $ranked_out/$cb.top_rank.list ]]; then
    fsize="empty"
    else
    fsize=$(file $ranked_out/$cb.top_rank.list | awk '{print $NF}') 
    fi
    
    echo "$TOOL_DIR/cgfl_status_pp.bash $destdir $cb \"$SEED\" $GROUND_TRUTH"
    $TOOL_DIR/cgfl_status_pp.bash $destdir $cb "$SEED" $GROUND_TRUTH
    if [[ -e $ranked_out/$cb.top_rank.list && $fsize != "empty" ]] ; then 
        echo "cgfl top rank : SUCCESS" >> $status_log ; 
    else 
        echo "cgfl top rank [ R issue ] : FAIL" >> $status_log; exit -1
    fi

fi
##########################################################################
# 3. Decompilation of CB for buggy function set => decomp source code
decomp_in=$decompdir/decomp_in
decomp_out=$decompdir/decomp_out
decomp_test=$decompdir/test/$cb

if (( ${EXECUTE[2]} == 1 )); then 
    if [[ ! -e $ranked_out/$cb.top_rank.list ]]; then
    echo "ERROR: decompilation error - missing $cb CGFL rank info"
    exit -1
    fi
    echo "Executing DECOMP stage"
    echo "-----------------------"
    (( ${RESET[2]} >= 0 )) && echo "Reseting DECOMP substage >= ${RESET[2]}" && rm -rf $decomp_test $decomp_in/$cb $decomp_out/$cb
    if [[ -e $decomp_in/$cb.target_list  ]]; then 
        echo "decompilation previously run for $cb"
    elif [[ ! -e $decomp_in/$cb.target_list  ]]; then 
        mkdir -p $decomp_in $decomp_out $decomp_test
    
       # note $decomp_out/$cb is generated by decompilation script
        buggy_set=$(/bin/cat $ranked_out/$cb.top_rank.list | perl -p -e's/(?<!:):(?!:)/ /g')
        i=0
        valid=""
        for f in ${buggy_set[*]}; do
            echo "Decompiling $f"
            din="$decomp_test/in"
            dout="$decomp_test/out.$i"
            mkdir -p $din $dout
            $TOOL_DIR/prdtools/decompile.py -p $cb_build/$cb --target-list $din/$cb.$i.target_list \
            -l $dout/multidecomp.log -o $dout -s $DECOMP_TOOL_DIR -f $f
            RET=$?
            #echo -n "$cb,$cb_build/$cb,$f" > $din/$cb.$i.target_list
            #python3 $DECOMP_TOOL_DIR/prd_multidecomp_ida.py --target_list \
            #$din/$cb.$i.target_list --ouput_directory $dout \
            #--scriptpath $DECOMP_TOOL_DIR/get_ida_details.py |& tee $dout/multidecomp.log
            #echo "====DONE====" >> $dout/multidecomp.log
            (( i+=1 ))
            ( [[ ! -e $dout/$cb ]] || (( $RET!=0 )) ) && echo "decompilation [Decompilation] $f : FAIL" >> $status_log && continue
            cp -v $TEMPLATES_DIR/Makefile.prd $dout/$cb/
            cp -v $TEMPLATES_DIR/script.ld $dout/$cb/
            cp -v $dout/$cb/${cb}_recomp.c $dout/$cb/${cb}_recomp.c.orig
            ln -sf $cb_build/test.sh $dout/$cb/
            ln -sf $cb_build/configuration-func-repair $dout/$cb/
            ln -sf $cb_build/poller $dout/$cb/
            ln -sf $cb_build/tools $dout/$cb/
            ln -sf $cb_build/$cb $dout/$cb/
            
            for j in $(ls $cb_build/pov*.pov); do 
            ln -sf $j $dout/$cb/
            done
            pushd $dout/$cb > /dev/null
            mkdir -p logs
            make -f Makefile.prd clean hook |& tee logs/make.decomp_hook.log-$i
            [[ ! -e libhook.so ]] && echo "decompilation [Recompilation] $f : FAILED" >> $status_log && popd > /dev/null &&  continue
            x=$(egrep -c 'Error\! Unbound functions\!' logs/make.decomp_hook.log-$i)
            (( $x>0 )) && echo "decompilation [Recompilation Symbol Binding] $f : FAILED" >> $status_log && popd > /dev/null &&  continue
            echo "decompilation [Recompilation Symbol Binding] $f : PASS" >> $status_log
            $TOOL_DIR/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${cb}_recomp.c
            diff --brief ${cb}_recomp.c ${cb}_recomp.c.orig &> /dev/null ; diff_ret=$?
            (( $?!=0 )) && echo "decompilation [Inline ASM Insertion] $f : FAIL" >> $status_log && exit -1
            [[ -e $cb.trampoline.bin ]] && rm $cb.trampoline.bin
            make -n -f  Makefile.prd clean hook funcinsert
            make -f Makefile.prd clean hook funcinsert |& tee logs/make.prd_build.log-$i
            [[ ! -e $cb.trampoline.bin ]] && echo "decompilation [PRD Binary] $f : FAIL" >> $status_log && popd > /dev/null && continue
            sanity_log="sanity.trampoline.log"
            echo "--------------------------------"
            echo "Running sanity tests on $f image"
            $TOOL_DIR/sanity.bash $cb.trampoline.bin -fail-fast |& tee logs/$sanity_log-$i
            retval=$?
            FAILED=$(tail -n 10 logs/$sanity_log-$i | egrep -c 'EXITING EARLY');
            if (( $FAILED>0 )); then
                echo "PRD [$f] sanity check [early fail] : FAIL" >> $status_log && popd > /dev/null && continue
            fi
            pos=$(tail -n 10 logs/$sanity_log-$i | egrep ' failed POSITIVE tests');
            neg=$(tail -n 10 logs/$sanity_log-$i | egrep ' failed NEGATIVE tests');
            negofail=$(tail -n 10 logs/$sanity_log-$i | egrep 'negotiation_failed NEGATIVE tests');
            pf=$(echo $pos | awk '{print $6}');
            pa=$(echo $pos | awk '{print $NF}');
            nf=$(echo $neg | awk '{print $6}');
            na=$(echo $neg | awk '{print $NF}');
            negof=$(echo $negofail | awk '{print $6}');
            negoa=$(echo $negofail | awk '{print $NF}');
            
            if (( $pf != 0 )); then
                echo "PRD [$f] sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : FAIL" >> $status_log && popd > /dev/null && continue
            elif (( $REQUIRE_NEG_TESTS_TO_FAIL==1 )) && (( $na != $nf )); then
                echo "PRD [$f] sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)][NEG-PASS] : FAIL " >> $status_log && popd > /dev/null && continue
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
        (echo -n "$cb,$cb_build/$cb,$valid") > $decomp_in/$cb.target_list
       
    fi

    if [[ ! -e $decomp_out/$cb ]] || [[ ! -e $decomp_out/$cb/${cb}_recomp.c ]]; then 
       $TOOL_DIR/prdtools/decompile.py -p $cb_build/$cb --target-list $decomp_in/$cb.target_list \
            -l $decomp_out/multidecomp.$cb.log -o $decomp_out -s $DECOMP_TOOL_DIR -f DUMMY
       #python3 $DECOMP_TOOL_DIR/prd_multidecomp_ida.py --target_list \
       # $decomp_in/$cb.target_list --ouput_directory $decomp_out \
       # --scriptpath $DECOMP_TOOL_DIR/get_ida_details.py |& tee $decomp_out/multidecomp.$cb.log
        mv $decomp_out/multidecomp.$cb.log $decomp_out/$cb/multidecomp.log
    fi 
    ([[ ! -e $decomp_out/$cb ]] || [[ ! -e $decomp_out/$cb/${cb}_recomp.c ]]) && echo "decompilation [Decompilation] : FAIL" >> $status_log && exit -1
    cp $TEMPLATES_DIR/Makefile.prd $decomp_out/$cb/
    cp $TEMPLATES_DIR/script.ld $decomp_out/$cb/
    ln -sf $cb_build/$cb $decomp_out/$cb/
    [[ ! -e $decomp_out/$cb/${cb}_recomp.c.orig ]] && cp $decomp_out/$cb/${cb}_recomp.c $decomp_out/$cb/${cb}_recomp.c.orig 

    pushd $decomp_out/$cb > /dev/null
        make -f Makefile.prd clean hook |& tee make.decomp_hook.log
        if [[ ! -e libhook.so ]]; then
           echo "Decompiled content failed to recompile for $cb!"
           echo "Exiting..."
           echo "decompilation [Recompilation] : FAIL" >> $status_log
           exit -1
        fi
        x=$(egrep -c 'Error\! Unbound functions\!' make.decomp_hook.log)
        (( $x>0 )) && echo "decompilation [Recompilation Symbol Binding] : FAILED" >> $status_log && exit -1
        $BASE_DIR/genprog_ida/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${cb}_recomp.c
        diff --brief ${cb}_recomp.c ${cb}_recomp.c.orig &> /dev/null ; diff_ret=$?
        (( $?!=0 )) && echo "decompilation [Inline ASM Insertion] $f : FAIL" >> $status_log && exit -1
        [[ -e $cb.trampoline.bin ]] && rm $cb.trampoline.bin
        make -n -f  Makefile.prd clean hook funcinsert
        make -f Makefile.prd clean hook funcinsert |& tee make.prd_build.log
    
    popd > /dev/null

    [[ ! -e $decomp_out/$cb/$cb.trampoline.bin ]] && echo "decompilation : FAIL" >> $status_log && exit -1
    [[ -e $decomp_out/$cb/$cb.trampoline.bin ]] && echo "decompilation : SUCCESS" >> $status_log 

fi
##########################################################################
# 4. Verify PRD image in build dir
if (( ${EXECUTE[3]} == 1 )); then 
    echo "Verifying PRD image for $cb"
    cp $decomp_out/$cb/Makefile.prd $cb_build/
    cp $decomp_out/$cb/script.ld $cb_build/
    cp $decomp_out/$cb/${cb}_recomp.c $cb_build/
    cp $decomp_out/$cb/defs.h $cb_build/
    cp $decomp_out/$cb/prd_include.mk $cb_build/
    cp $decomp_out/$cb/prd_info.json $cb_build/
    cp $decomp_out/$cb/resolved-types.h $cb_build/
    #cp $decomp_out/$cb/$cb.trampoline.bin $cb_build/
   
   pushd $cb_build > /dev/null
    make -f Makefile.prd clean hook funcinsert |& tee make.decomp_hook.log
    if [[ ! -e $cb.trampoline.bin ]]; then 
        echo "Failed to recompile $cb.trampoline.bin [$cb_build]"
        echo "Recompilation : FAIL " >> $status_log && exit -1
    fi
    sanity_log="sanity.trampoline.log"
    $TOOL_DIR/sanity.bash $cb.trampoline.bin -fail-fast |& tee $sanity_log
    FAILED=$(tail -n 1 $sanity_log | egrep -c 'EXITING EARLY');
    if (( $FAILED==1 )); then
        echo "PRD sanity check [early fail] : FAIL" >> $status_log && exit -1
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
        echo "PRD sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : FAIL" >> $status_log && exit -1
    elif (( $pf != 0 )); then
        echo "PRD sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : FAIL" >> $status_log && exit -1
    else 
        echo "PRD sanity check [pos($pf/$pa);neg($nf/$na);negotiation($negof/$negoa)] : SUCCESS" >> $status_log
    fi;
   
   popd > /dev/null

fi
##########################################################################
# 5. Performance capturing
cb_perf="$perfdir/$cb"
det_perf="$perfdir/${cb}_detour"
perf="perf_log"
if (( ${EXECUTE[4]} == 1 )); then 
  if [[ -e $cb_build/$cb  || -e $cb_build/$cb.trampoline.bin ]]; then 
     mkdir -p $cb_perf $det_perf
     $TOOL_DIR/convert_test_to_perf.bash $cb --src=$builddir --logdir=$perf ;
     
     if [[ -e $cb_build/$cb ]]; then 
        pushd $cb_build
        mkdir -p $perf
        echo "Running performance test on $cb"
        $TOOL_DIR/sanity_perf.bash $cb --logdir=$cb_perf --outdir=$perf &> $cb.perf.log
        #mv $perf $cb_perf
        popd
     fi;
     if [[ -e $cb_build/$cb ]]; then 
        pushd $cb_build
        mkdir -p $perf
        echo "Running performance test on $cb.trampoline.bin"
        $TOOL_DIR/sanity_perf.bash $cb.trampoline.bin --logdir=$det_perf --outdir=$perf &> $cb.perf.log
        #mv $perf $det_perf
        popd
     fi;
  fi
fi
##########################################################################
# 6. APR setup for CB with decomp source code => repairs
if (( ${EXECUTE[5]} == 1 )); then 
   echo "APR set up for $cb"
   (( ${RESET[5]} == 1 )) &&  rm -rf $aprdir/prd_src/$cb $aprdir/genprog_/$cb.* $aprdir/prophet_/cfg/$cb $aprdir/revlog/$cb.* $aprdir/scripts/*.$cb*.bash
   (( ${RESET[5]} == 1 )) && [[ -e $aprdir/scripts/APR.p_reg.bash ]] && perl -pi -e'if(/Processing '"$cb"'/){ $delete=1;} if ($delete){ if(/DONE - Processing '"$cb"' /){$delete=0;}; undef $_;}' $aprdir/scripts/APR.gp_reg.bash $aprdir/scripts/APR.p_reg.bash
   mkdir -p $aprdir
   echo $TOOL_DIR/generate_apr_cfg.py --dest-dir $(realpath $aprdir) --src-dir $cb_build --prophet-exe $prophetexe
   $TOOL_DIR/generate_apr_cfg.py --dest-dir $(realpath $aprdir) --src-dir $cb_build --prophet-exe $prophetexe
   # this should create a bunch of scripts in $aprdir/scripts/
   echo "GenProg Scripts: "
   ls $aprdir/scripts/gp.$cb.pov*.bash 
   echo "Prophet Script: "
   ls $aprdir/scripts/prophet.$cb.bash
   echo '#!/bin/bash' > $aprdir/scripts/APR.$cb.bash
   ls $aprdir/scripts/gp.$cb.pov*.bash | sed 's/$/&/' >> $aprdir/scripts/APR.$cb.bash
   ls $aprdir/scripts/prophet.$cb.bash >> $aprdir/scripts/APR.$cb.bash
   chmod +x $aprdir/scripts/APR.$cb.bash
   echo -e "To run individual APR on $cb:\n$aprdir/scripts/APR.$cb.bash "
   x=0
   for i in $apr_regression $apr_gp_reg $apr_p_reg; do 
    if [[ ! -e $i ]]; then
       echo -e '#!/bin/bash\n' > $i
       chmod +x $i
       if (( $x == 0 )); then 
            echo "$apr_gp_reg &" >> $apr_regression
            echo "$apr_p_reg" >> $apr_regression
            (( x+=1 ))
       fi
    fi
   done
   echo "echo \"Processing $cb \"" >> $apr_gp_reg
   echo "echo \"Processing $cb \"" >> $apr_p_reg

   gpscripts=$(ls $aprdir/scripts/gp.$cb.pov*.bash | sed 's/\.bash/\.bash \\/g')"\n"
   echo -e "\nfor i in $gpscripts ; do\n while (( \$(jobs|wc -l)>=10 )); do sleep 3600; done;\n\t \$i& \ndone" \
       >> $apr_gp_reg
   echo $aprdir/scripts/prophet.$cb.bash >> $apr_p_reg
   echo "echo \"DONE - Processing $cb \"" >> $apr_gp_reg
   echo "echo \"DONE - Processing $cb \"" >> $apr_p_reg
   echo "APR set up : SUCCESS" >> $status_log

fi
############################################################################

exit 0
