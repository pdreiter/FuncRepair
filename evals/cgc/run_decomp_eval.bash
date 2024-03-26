#!/bin/bash

SCRIPTDIR=$(dirname -- $(realpath -- ${BASH_SOURCE[0]}))
CB=$1
DIR_ID=$2
FUNC_NUM=$3

DECOMP_TARGETS=decomp_targets
DECOMP_OUTPUT=decomp_eval$DIR_ID/out
DECOMP_RECOMPILE=decomp_eval$DIR_ID/recomp
DECOMP_LOGS=decomp_eval$DIR_ID/logs

TARGETS=()
if [[ -z $FUNC_NUM ]]; then 
  TARGETS=$(ls $DECOMP_TARGETS/$CB.target_list.*)
else
  TARGETS=$(ls $DECOMP_TARGETS/$CB.target_list.$FUNC_NUM)
fi

mkdir -p $DECOMP_OUTPUT $DECOMP_RECOMPILE $DECOMP_LOGS
for TARGET in ${TARGETS[@]}; do
  id=$(echo $TARGET | cut -d "." -f 3)
  $SCRIPTDIR/rerun_recomp_decomp.bash $CB $id $DECOMP_TARGETS $DECOMP_OUTPUT $DECOMP_RECOMPILE $DECOMP_LOGS 
  echo "[Completed][$CB] Function $id"
done

echo "[Completed] $CB"
