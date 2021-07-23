#!/bin/bash
destdir=prd_e2e
filelist=$1
if [[ ! -z $2 ]]; then 
destdir=$2
fi
seed=
if [[ ! -z $3 ]]; then 
seed=$3
fi
scriptdir=$(dirname $0)

for i in $(cat $filelist); do 
    $scriptdir/cgfl_status_pp.bash $destdir $i $seed
done 

