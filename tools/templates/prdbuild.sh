#!/bin/bash
PRD_BASE_DIR=<PRD_BASE_DIR>
DIET32PATH=$PRD_BASE_DIR/stdlib-src/dietlibc/dietlibc-0.34/bin-i386
DIET64PATH=$PRD_BASE_DIR/stdlib-src/dietlibc/dietlibc-0.34/bin-x86_64
SCRIPT_DIR=$(dirname -- $(realpath -- ${BASH_SOURCE[0]}))
exe_out=$1
in_src=$2

if [[ ! -z $exe_out ]] && [[ ! -z $in_src ]]; then
isrc=$(echo $in_src | perl -p -e"s#$SCRIPT_DIR/##")
echo "MYSRC=$isrc"
if [[ ! -e ${in_src}.prev ]]; then 
  cp $in_src ${in_src}.prev
  srcf=$(basename -- $isrc)
fi
# let's get rid of CIL's bad introduction of __builtin_va_list when we have our own variadic function
perl -pi -e's/__builtin_va_start\(\(__builtin_va_list \)argptr,/__builtin_va_start(argptr,/' $in_src
perl -pi -e's/__builtin_va_end\(\(__builtin_va_list \)argptr\)/__builtin_va_end(argptr)/' $in_src
DETOUR_BIN=$exe_out MYSRC=$isrc make -f Makefile.prd clean_hook hook funcinsert
else
make -f Makefile.prd clean_hook hook funcinsert
fi

