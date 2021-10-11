#!/bin/bash
# This revlog_prophet.bash script generates the full-source Prophet input files

SCRIPT_DIR=$(dirname $(realpath $0))
ROOT_DIR=${CGC_CB_DIR}
IN_CGC_TEST=$ROOT_DIR/cgc_test
POLLS=$ROOT_DIR/polls

MY_PROPHET_PATH=$PROPHET64_BASE
if [[ -z $MY_PROPHET_PATH ]]; then
    echo "ERROR! Prophet path not set! expecting \$PROPHET64_BASE to be set to prophet-gpl directory"
    exit -1
fi
if [[ ! -d $IN_CGC_TEST  && -d cgc_test ]]; then
    IN_CGC_TEST=$(realpath -- ./cgc_test)
fi
if [[ ! -d $POLLS  && -d polls ]]; then
    POLLS=$(realpath -- ./polls)
fi

TEST=$1
CFG_DEST=$2
RUN_DEST=$3

mkdir -p pchallenges/$TEST.src ptest/ pbin/
cp -r $IN_CGC_TEST/$TEST ptest/
ln -sf $(realpath -- $POLLS/$TEST/poller) ptest/$TEST/
ln -sf $(realpath -- $PRD_BASE_DIR/tools) ptest/$TEST/

#cp -r $CGC_CB_DIR/challenges/$TEST pchallenges/$TEST.src/
#ln -sf $CGC_CB_DIR/include pchallenges/$TEST.src/
#cp -r $SCRIPT_DIR/CMakeLists.txt pchallenges/$TEST.src/
#ln -sf ${SCRIPT_DIR}/CMakeLists.txt .
cp ${SCRIPT_DIR}/cgc-build.py pbin/
cp ${SCRIPT_DIR}/cgc-test.py pbin/
cp ${SCRIPT_DIR}/tester_common.py pbin/
ln -sf ${SCRIPT_DIR}/CMakeLists.txt pbin/
ln -sf $(realpath -- $POLLS) pbin/
ln -sf $(realpath -- $PRD_BASE_DIR/tools/cb-multios) pbin/tools
ln -sf $(realpath -- $CGC_CB_DIR/include) pbin/include

CGC_TEST=$(realpath -- ptest)
#CGC_SRC=$(realpath -- pchallenges/$TEST.src)
CGC_SRC=$(realpath -- $CGC_CB_DIR/challenges/$TEST)
CGC_BIN=$(realpath -- pbin)

[[ ! -e ${CFG_DEST} ]] && mkdir ${CFG_DEST} 
DEST=$(realpath "${CFG_DEST}")"/${TEST}"
#DEST=$(realpath "${CFG_DEST}/${TEST}")

BASEREVLOG=${TEST}
REVLOGEXT="revlog"
CONFEXT="conf"

SRC_DIR="${ROOT_DIR}/challenges/${TEST}"
# this is the artificial directory we're moving the build dir into
REL_SRC_DIR="cb_src/${TEST}"
PATCHED_FILENAMES=$(ls ${SRC_DIR}/src/*.c*  | perl -p -e"s#${SRC_DIR}/#${REL_SRC_DIR}/#;s#\s*\$# #")

neg=$(egrep 'neg\-tests' $CGC_TEST/$TEST/configuration-func-repair | awk '{print $NF}')
pos=$(egrep 'pos\-tests' $CGC_TEST/$TEST/configuration-func-repair | awk '{print $NF}')

if [[ ! -e ${DEST} ]]; then 
mkdir -p ${DEST}
fi
#NUM=10;
#EXE=Message_Service.trampoline.bin ;
i=0
k=0
REVLOG="${DEST}/${BASEREVLOG}.all.${REVLOGEXT}"
CONF="${DEST}/${BASEREVLOG}.all.${CONFEXT}"
echo "-" > $REVLOG
echo "-" >> $REVLOG
neglimit=$(($neg-1))
echo "Diff Cases: Tot $neg" >> $REVLOG
for k in $(seq 0 $neglimit); do
      indx="$k"
      echo -n "$indx " >> $REVLOG
done
echo "" >> $REVLOG
echo "Positive Cases: Tot $pos" >> $REVLOG
k=$neg
for i in $(seq $k $pos); do
      indx="$i"
      echo -n "$indx " >> $REVLOG
done
echo "" >> $REVLOG
echo "Regression Cases: Tot 0" >> $REVLOG

echo "revision_file=${REVLOG}" > ${CONF}
echo "src_dir=${CGC_SRC}" >> ${CONF}
echo "test_dir=${CGC_TEST}/${TEST}" >> ${CONF}
echo "build_cmd=${CGC_BIN}/cgc-build.py" >> ${CONF}
echo "test_cmd=${CGC_BIN}/cgc-test.py" >> ${CONF}
echo "localizer=profile" >> ${CONF}
echo "bugged_file=${PATCHED_FILENAMES}" >> ${CONF}
echo "fixed_out_file=prophet_repair_${TEST}_" >> ${CONF}
echo "single_case_timeout=7" >> ${CONF}
echo "wrap_ld=no" >> ${CONF}
echo "challenge=${TEST}" >> ${CONF}
echo "makefile=Makefile.cgc" >> ${CONF}
echo "makefile_target=all" >> ${CONF}
conf_path=$(dirname $(realpath $CONF))


for A in $(seq 1 $neg); do
CONF="${DEST}/${BASEREVLOG}.pov_${A}.${CONFEXT}"
REVLOG="${DEST}/${BASEREVLOG}.pov_${A}.${REVLOGEXT}"
echo "-" > $REVLOG
echo "-" >> $REVLOG
echo "Diff Cases: Tot 1" >> $REVLOG
indx=$(($A-1))
echo -n "$indx " >> $REVLOG
echo "" >> $REVLOG
echo "Positive Cases: Tot $pos" >> $REVLOG
k=$neg
for i in $(seq $k $pos); do
      indx="$i"
      echo -n "$indx " >> $REVLOG
done
echo "" >> $REVLOG
echo "Regression Cases: Tot 0" >> $REVLOG

# generate pov-specific .conf file
echo "revision_file=${REVLOG}" > ${CONF}
echo "src_dir=${CGC_SRC}" >> ${CONF}
echo "test_dir=${CGC_TEST}/${TEST}" >> ${CONF}
echo "build_cmd=${CGC_BIN}/cgc-build.py" >> ${CONF}
echo "test_cmd=${CGC_BIN}/cgc-test.py" >> ${CONF}
echo "localizer=profile" >> ${CONF}
echo "bugged_file=${PATCHED_FILENAMES}" >> ${CONF}
echo "fixed_out_file=prophet_repair_${TEST}_pov_${A}_" >> ${CONF}
echo "single_case_timeout=7" >> ${CONF}
echo "wrap_ld=no" >> ${CONF}
echo "challenge=${TEST}" >> ${CONF}
echo "makefile=Makefile.cgc" >> ${CONF}
echo "makefile_target=all" >> ${CONF}

done

mkdir -p ${RUN_DEST}/scripts ${RUN_DEST}/logs
out=${RUN_DEST}/scripts/${TEST}.bash 
frunpath=$(realpath -- $RUN_DEST)
echo '#!/bin/bash' > ${out}
echo "export PROPHET64_BASE=$MY_PROPHET_PATH" >> ${out}
echo "cd $frunpath" >> ${out}
echo "mkdir -p logs/${TEST} runs/${TEST}; curdir=\$(pwd); pushd runs/${TEST} > /dev/null" >> ${out}
for A in $(seq 1 $neg); do
echo "\${PROPHET64_BASE}/src/prophet $conf_path/${TEST}.pov_${A}.conf -r ${TEST}.pov_${A} -vl=10 -ll=10 >& \$curdir/logs/${TEST}/${TEST}.pov_${A}.log" >> ${out}
done
echo "popd > /dev/null; echo \"Done - ${TEST}\"" >> ${out}
chmod +x ${out}


echo "DONE - $TEST"
