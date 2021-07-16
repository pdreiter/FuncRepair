#!/bin/bash
# This revlog_prophet.bash script generates the full-source Prophet input files

SCRIPT_DIR=$(dirname $(realpath $0))
ROOT_DIR=$(dirname ${SCRIPT_DIR})
TEST=$1
CFG_DEST=$2
RUN_DEST=$3

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

neg=$(egrep 'neg\-tests' $ROOT_DIR/genprog/$TEST/configuration-func-repair | awk '{print $NF}')
pos=$(egrep 'pos\-tests' $ROOT_DIR/genprog/$TEST/configuration-func-repair | awk '{print $NF}')

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
echo "src_dir=${ROOT_DIR}/challenges/${TEST}" >> ${CONF}
echo "test_dir=${ROOT_DIR}/genprog/${TEST}" >> ${CONF}
echo "build_cmd=${SCRIPT_DIR}/cgc-build.py" >> ${CONF}
echo "test_cmd=${SCRIPT_DIR}/cgc-test.py" >> ${CONF}
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
echo "src_dir=${ROOT_DIR}/challenges/${TEST}" >> ${CONF}
echo "test_dir=${ROOT_DIR}/genprog/${TEST}" >> ${CONF}
echo "build_cmd=${SCRIPT_DIR}/cgc-build.py" >> ${CONF}
echo "test_cmd=${SCRIPT_DIR}/cgc-test.py" >> ${CONF}
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
echo '#!/bin/bash' > ${out}
echo 'export PROPHET64_BASE=MY_PROPHET_PATH' >> ${out}
echo "mkdir -p logs/${TEST} runs/${TEST}; curdir=\$(pwd); pushd runs/${TEST} > /dev/null" >> ${out}
for A in $(seq 1 $neg); do
echo "\${PROPHET64_BASE}/src/prophet $conf_path/${TEST}.pov_${A}.conf -r ${TEST}.pov_${A} -vl=10 -ll=10 >& \$curdir/logs/${TEST}/${TEST}.pov_${A}.log" >> ${out}
done
echo "popd > /dev/null; echo "Done - ${TEST}" >> ${out}
chmod +x ${out}

