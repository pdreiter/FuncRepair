#!/bin/bash
NUM=$1
DATE=$2

# if we do static builds
STATICBUILD=1
# this is the outstanding parallel jobs
if [[ -z $NUM ]]; then NUM=16; fi
# this is the time of the launch or other identifier
if [[ -z $DATE ]]; then 
    DATE=$(date +"%H.%M-%m.%d.%Y")
fi

MYE2E="./e2e_cgfl_recomp.bash"

# ensuring that basic infrastructure exists here
for x in cpp_xlist decomp_xlist; do
if [[ ! -e $x ]]; then cp $PRD_BASE_DIR/tools/cb-multios/$x .; fi
done
# reducing EXECUTION to just basic setup, CGFL, decomp, recomp
#EXECUTE=( 1 1 1 1 0 1 ) => EXECUTE=( 1 1 1 1 0 0 )
perl -p -e's/EXECUTE=\( 1 1 1 1 0 1 \)/EXECUTE=( 1 1 1 1 0 0 )/;s/^REQUIRE_NEG_TESTS_TO_FAIL=1$/REQUIRE_NEG_TESTS_TO_FAIL=0/' $PRD_BASE_DIR/tools/binrepared_e2e.bash > $MYE2E
if (( $STATICBUILD==1 )); then 
perl -pi -e's/-DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF/-DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON/g' $MYE2E
fi
# if you're rerunning sub-stages:
# CHANGE 1: reducing EXECUTION to reuse basic setup, CGFL, rerun decomp and recomp
# perl -p -e's/EXECUTE=\( 1 1 1 1 0 1 \)/EXECUTE=( 0 0 1 1 0 0 )/;s/^REQUIRE_NEG_TESTS_TO_FAIL=1$/REQUIRE_NEG_TESTS_TO_FAIL=0/' $PRD_BASE_DIR/tools/binrepared_e2e.bash > $MYE2E
chmod +x $MYE2E
if [[ ! -d patched_functions ]]; then
  patched_tgz="$PRD_BASE_DIR/tools/cb-multios/patched_functions.tgz"
  echo "Obtaining CGC Ground Truth from $patched_tgz"
  tar -xvzf $patched_tgz .
fi


# basic output and log variables
OUTDIR="cgfl_recomp.$DATE"
LOGDIR="logs.$DATE"

#CBs=$(cat decomp_xlist)

for i in $(cat cpp_xlist decomp_xlist); do 
    if (( $(egrep -c $i cpp_xlist)==0 )); then 
        PREFIX="cgc_c"; 
    else 
        PREFIX="cgc_cpp"; 
    fi 
    mkdir -p ${PREFIX}.${LOGDIR}
    j=$(ps -a -f |& egrep $(basename -- $MYE2E) | egrep -vw 'grep' | wc -l); 
    while (( $j>=$NUM )); do 
        sleep 600; 
        j=$(ps -a -f |& egrep $(basename -- $MYE2E) | egrep -vw 'grep' | wc -l); 
    done; 
    # skip CBs that have already been built
    if [[ ! -d $PREFIX.$OUTDIR/build/$i ]]; then 
        ( $MYE2E $i $PREFIX.$OUTDIR; echo -e "\n--- DONE : $i\n $i STATUS: ";cat ${PREFIX}.${OUTDIR}/status/$i.log ) &> ${PREFIX}.${LOGDIR}/$i.cgfl_recomp.log &
    fi
    # CHANGE 2: reducing EXECUTION to reuse basic setup, CGFL, rerun decomp and recomp
    # skip CBs that have already been decompiled (append to log)
    #if [[ ! -d $PREFIX.$OUTDIR/decomp/test/$i ]]; then 
    #    ( $MYE2E $i $PREFIX.$OUTDIR; echo -e "\n--- DONE : $i\n $i STATUS: ";cat ${PREFIX}.${OUTDIR}/status/$i.log ) >> ${PREFIX}.${LOGDIR}/$i.cgfl_recomp.log 2>&1 &  
    #fi
done

echo "DATE=$DATE"
echo "CGC C LOGFILES="
ls cgc_c.$LOGDIR/*.cgfl_recomp.log
echo "CGC C++ LOGFILES="
ls cgc_cpp.$LOGDIR/*.cgfl_recomp.log
