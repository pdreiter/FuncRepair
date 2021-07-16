#!/bin/bash

#NUM=10;
#EXE=Message_Service.trampoline.bin ;
EXE=$1
TESTME=${@:2:$#}
passing=()
DEBUG=0
num_tests=$#-2
i=0
j=0
   for TEST in ${TESTME[@]}; do
      ./test.sh $EXE $TEST > /dev/null 2>&1;
      x=$?
      val="PASSED"
      if [[ $x -ne 0 ]]; then
      (( j+=1 ));
      val="FAILED";
	  else
	  passing+=(${TEST})
      fi;
	  if [[ $DEBUG -ne 0 ]]; then 
      echo -e "[$i] status $x => $val $TEST TEST!";
	  fi;
      (( i+=1 ));
   done
   if [[ $DEBUG -ne 0 ]]; then 
   echo "# of failed tests $j of $#"
   fi
   echo "${passing[@]}"
