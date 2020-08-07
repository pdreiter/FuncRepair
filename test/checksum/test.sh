#!/bin/bash
# $1 = EXE 
# $2 = test name  
# $3 = port 
# $4 = source name
# $5 = single-fitness-file name 
# exit 0 = success

# update on 4/22 based on feedback from Pad - try timeout in test scenario
#ulimit -t 1
echo $1 $2 $3 $4 $5 >> testruns.txt
bin=$1
tst=$2


python_ver=$(which python3.7)


EXIT_SCENARIO=1

case $2 in
  # Let's walk through the 4 invalid scenarios
  p1) 
    value="12345"
  ;;
  p2) 
    value="xYZfx15"
  ;;
  p3) 
    value="abcdef12345"
  ;;
  p4) 
    value="AAAAAA"
  ;;
  # negative test case 
  n1) 
    value="012345"
  ;;
  *)
  echo "INVALID TESTCASE"
  EXIT_SCENARIO=1
  ;;


esac 


x=$($bin $value)
y=$($python_ver pychecker.py $value)
if [ "$x" == "$y" ]; then
   EXIT_SCENARIO=0
fi
exit $EXIT_SCENARIO

