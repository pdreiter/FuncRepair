#!/bin/bash

# this script generates a compatible source directory for prophet-prd
#  - more up to date script : generate_apr_cfg.py
SCRIPT_DIR=$(dirname $(realpath $0))
PRD_TOOL=${PRD_BASE_DIR}/funcinsert.py
CGC_TOOL_DIR=${PRD_BASE_DIR}/tools/cb-multios

ROOT_DIR=${CGC_CB_DIR}
PRD_SRC=${ROOT_DIR}/cgc_test/${TEST}
DEST=${ROOT_DIR}/pchallenges/${TEST}
BUILD_DIR=${ROOT_DIR}/build/challenges/${TEST}


TEST=$1

[[ ! -d "${PRD_SRC}" ]] && echo "ERROR: PRD source @ ${PRD_SRC} doesn't exist" && exit -1; 
[[ ! -e "${ROOT_DIR}/build/challenges/${TEST}/${TEST}" ]] && echo "ERROR: ${TEST} CB has not been compiled!" && exit -1;
[[ ! -e "${ROOT_DIR}/build/challenges/${TEST}/poller" ]] && echo "ERROR: ${TEST} CB test infrastructure has not been generated!" && exit -1;


[[ ! -d $DEST ]] && mkdir -p $DEST

cp -d -r ${PRD_SRC}/* $DEST/
for i in ${TEST} pov_*.pov poller ; do 
cp -n -d ${BUILD_DIR}/${i} ${DEST}/
done
ln -sf $PRD_TOOL ${DEST}/
ln -sf $CGC_TOOL_DIR ${DEST}/tools
ln -sf ${SCRIPT_DIR}/Makefile.prophet ${DEST}/



