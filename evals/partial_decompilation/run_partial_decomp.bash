#!/bin/bash

SCRIPTDIR=$(dirname -- $(realpath -- ${BASH_SOURCE[0]}))

if [[ -z $IDA_BASE_DIR ]] ; then 
   echo "IDA / Hex-Rays is not set up"
   echo "Please set \$IDA_BASE_DIR to IDA Hex-Rays installation directory"
   exit -1
fi
if [[ ! -e $CGC_CB_DIR/polls ]] ; then 
   echo "CGC Tests have not been generated or downloaded!"
   exit -1
fi
if [[ ! -d $CGC_CB_DIR/cgc_test ]] ; then 
   echo "Test Evaluation Infrastructure has not been set up"
   exit -1
fi

DECOMP_TARGETS=decomp_targets

#DATE=$(date +"%H.%M-%m.%d.%Y")
DIR_ID=$1

CBLIST=$SCRIPTDIR/decomp_xlist

if [[ ! -d $SCRIPTDIR/$DECOMP_TARGETS ]] ; then 
   pushd $SCRIPTDIR
   tar -xvzf $DECOMP_TARGETS.tgz
   perl -pi -e"s#/media/external/research/CGC_GENPROG/FuncRepair/#$PRD_BASE_DIR/#g;" $DECOMP_TARGETS/*.target_list.*
   popd
fi


RUNIT=1
for cb in $(cat $CBLIST); do
  if [[ ! -d decomp_eval$DIR_ID/out/$cb.0 ]] ; then 
      if [[ -d $CGC_CB_DIR/cgc_test/$cb ]]; then 
          $SCRIPTDIR/run_decomp_eval.bash $cb $DIR_ID
	  else
	     RUNIT=0
      fi
  fi
done

if (( $RUNIT==1 )); then 

$SCRIPTDIR/get_decomp_results.bash $DIR_ID

fi
