#!/bin/bash

CB=$1
ID=$2
INPUT_DIR=$3 # where <CB>.target_list.<ID> is located
OUTPUT_DIR=$4
RECOMP_DIR=$5
LOGDIR=$6
DECOMP_DIR=$(realpath -- ./decomp_dir)
LOGFILE=$LOGDIR/$CB.$ID.log

mkdir -p $OUTPUT_DIR $RECOMP_DIR $LOGDIR

decompile() {
i=$1  # $CB
x=$2  # $ID
target=$INPUT_DIR
dest=$OUTPUT_DIR
log=$(realpath -- $LOGFILE)

prog=$(cat $target/$i.target_list.$x | cut -d "," -f 2)
funcs=$(cat $target/$i.target_list.$x | perl -p -e's/^([^,]+),([^,]+),(.*)$/$3/' | perl -p -e's/:/ -f /g;')
echo "timeout --preserve-status -k 2h 2h python3 $PRD_BASE_DIR/tools/prdtools/decompile.py --decompdir $DECOMP_DIR --target-list $target/$i.target_list.$x --out $dest -s $PART_DECOMP_DIR -l $dest/ida.$i.$x.log -p $prog -f $funcs "
timeout --preserve-status -k 2h 2h python3 $PRD_BASE_DIR/tools/prdtools/decompile.py --decompdir $DECOMP_DIR --target-list $target/$i.target_list.$x --out $dest -s $PART_DECOMP_DIR -l $dest/ida.$i.$x.log -p $prog -f $funcs 
RET=$?
if (( $(egrep -c "Nothing to do. Exiting." $dest/ida.$i.$x.log)>0 )); then
    echo "decompilation : N/A : $i.$x" > $log
    exit -1
elif [[ ! -d "$dest/$i" ]]; then
    echo "decompilation : FAILED : $i.$x" > $log
    exit -1
elif [[ ! -e "$dest/$i/${i}_recomp.c" ]]; then
    echo "decompilation : FAILED : $i.$x" > $log
    exit -1
#if [[ -e "$dest/$i" ]]; then
else
    mv -v $dest/$i $dest/$i.$x
    x_list=$xlist" $x"
    echo "decompilation : PASSED : $i.$x" > $log
fi

}

build_recompile() {
i=$1 # $CB
x=$2 # $ID
dest=$OUTPUT_DIR
rdest=$RECOMP_DIR
log=$(realpath -- $LOGFILE)

if [[ ! -d "$rdest/$i" ]]; then
  mkdir -p $rdest/logs
  if [[ ! -d $rdest/$i.base ]]; then 
    mkdir -p $rdest/$i.base 
    for k in ${i} "pov_*.pov" ; do 
      cp $CGC_CB_DIR/build32/challenges/$i/$k $rdest/$i.base/;
    done;
    for k in "configuration-func-repair" "test*.sh" ; do 
      ln -sf $(realpath $CGC_CB_DIR/cgc_test/$i)/$k $rdest/$i.base/
    done
    ln -sf $(realpath $PRD_BASE_DIR/tools/templates/Makefile.prd) $rdest/$i.base/
    ln -sf $(realpath $PRD_BASE_DIR/tools/templates/script.ld) $rdest/$i.base/
    ln -sf $(realpath $CGC_CB_DIR/polls/$i)/poller $rdest/$i.base/
  fi
fi
if [ -d $rdest/$i/src.$x ]; then
  rm -rf $rdest/$i/src.$x
fi

[[ -e $rdest/$i.$x ]] && rm -rf $rdest/$i.$x
cp  -r $rdest/$i.base $rdest/$i.$x
cp $dest/$i.$x/${i}_recomp.c $dest/$i.$x/${i}_recomp.c-noasm 
cp  $dest/$i.$x/* $rdest/$i.$x/

echo -e "#!/bin/bash\npushd $rdest/$i.$x &> /dev/null;\nID=\$1;\nmkdir -p ../logs\n\
  perl -pi -e's#; weak#; // weak#' basic.c\n\
  make -f Makefile.prd clean hook funcinsert &> ../logs/make\$ID.$i.$x.log\n\
  make -f Makefile.prd basic &> ../logs/make.basic.\$ID.$i.$x.log\n\
 popd &> /dev/null" > $rdest/build.$i.$x.bash
echo -e "#!/bin/bash\npushd $rdest/$i.$x &> /dev/null;\n\
  ID=\$1;\n \
  ret=1; \n\
  BSTR=""; \n\
  if [[ ! -e depobj/basic.o ]]; then \n\
      BSTR=\"basic\$ID : FAILED : $i.$x\"; \n\
      ret=1; \n\
  else \n\
      BSTR=\"basic\$ID : PASSED : $i.$x\"; \n\
      ret=0; \n\
  fi; \n\
  echo \$BSTR >> $log; \n\
  popd &> /dev/null; \n\
  exit \$ret" > $rdest/eval_basic.$i.$x.bash
echo -e "#!/bin/bash\npushd $rdest/$i.$x &> /dev/null;\n\
  ID=\$1;\n \
  ret=1; \n\
  if [[ ! -e libhook.so ]] || [[ ! -e ${i}.trampoline.bin ]]; then \n\
      STR=\"recompilation\$ID : FAILED : $i.$x\"; \n\
      ret=1; \n\
  else \n\
      STR=\"recompilation\$ID : PASSED : $i.$x\"; \n\
      ret=0; \n\
  fi; \n\
  echo \$STR >> $log; \n\
  popd &> /dev/null; \n\
  exit \$ret" > $rdest/eval_recomp.$i.$x.bash
  echo -e "#!/bin/bash\n\npushd $rdest/$i.$x &> /dev/null; \
  $PRD_BASE_DIR/tools/create_asm_multidetour.py --json-in prd_info.json --file-to-objdump libhook.so --source ${i}_recomp.c &> ../logs/detmake.$i.$x.log; \
  make -f Makefile.prd clean hook funcinsert &> ../logs/makeprd.$i.$x.log; \
popd &> /dev/null" > $rdest/reconasm.$i.$x.bash
echo -e "#!/bin/bash\npushd $rdest/$i.$x &> /dev/null; \n\
ret=1 \n\
if [[ ! -e ${i}.trampoline.bin ]]; then exit -1; fi; \n\
\$PRD_BASE_DIR/tools/sanity.bash ${i}.trampoline.bin -fail &> ../logs/run.$i.$x.log ;\n\
if (( \$(egrep -c 'EXITING EARLY Due to failures' ../logs/run.$i.$x.log)>0 )); then \
  STR=\"test-equivalence : FAILED : $i.$x\"; \n\
  ret=1; \
elif (( \$(egrep -c 'Returning 0' ../logs/run.$i.$x.log)==0 )); then \
  XX=\$(egrep \"of failed NEGATIVE tests\" ../logs/run.$i.$x.log | perl -p -e's/.*(\d+) of \d+.*$/\$1/) 
  STR=\"test-equivalence : FAILED-PASSING-NEG-\$XX : $i.$x\"; \n\
  ret=0; \
else \
  STR=\"test-equivalence : PASSED : $i.$x\"; \n\
  ret=0; \
fi;\n\
echo \$STR >> $log; \n\
popd &> /dev/null; \n\
exit \$ret" >> $rdest/test.$i.$x.bash 

chmod +x $rdest/test.$i.$x.bash \
 $rdest/build.$i.$x.bash \
 $rdest/eval_basic.$i.$x.bash \
 $rdest/eval_recomp.$i.$x.bash \
 $rdest/reconasm.$i.$x.bash

$rdest/build.$i.$x.bash "";
$rdest/eval_basic.$i.$x.bash ""; RET=$?
if (( $RET!=0 )); then
echo "[decompile][recompile][basic] $i.$x FAILED"
else
echo "[decompile][recompile][basic] $i.$x SUCCESS"
fi
$rdest/eval_recomp.$i.$x.bash ""; RET=$?
if (( $RET!=0 )); then
echo "[decompile][recompile][wo-asm] $i.$x FAILED"
else
  echo "[decompile][recompile][wo-asm] $i.$x SUCCESS"
  $rdest/build.$i.$x.bash "-w-asm"
  $rdest/reconasm.$i.$x.bash
  $rdest/eval_recomp.$i.$x.bash "-w-asm"
  if (( $?==0 )); then
      echo "[decompile][recompile][w-asm] $i.$x SUCCESS"
      $rdest/test.$i.$x.bash
      if (( $?==0 )); then
          echo "[decompile][recompile][w-asm][test-equiv] $i.$x SUCCESS"
      else
          echo "[decompile][recompile][w-asm][test-equiv] $i.$x FAILED"
      fi
  else
      echo "[decompile][recompile][w-asm] $i.$x FAILED"
  fi
fi
}


decompile "$CB" "$ID";
build_recompile "$CB" "$ID";

