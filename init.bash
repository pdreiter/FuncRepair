#!/bin/bash

#-----------------------------------------------------
# tihs script should be source'd to allow ENV variables
# to be exported to encompassing environment
#-----------------------------------------------------

libinstall_dir="stdlib-src"

glibc_ver="2.31"
dietlibc_ver="0.34"
cwd=$(realpath .)

if [[ ! -d "${libinstall_dir}/glibc-${glibc_ver}" ]]; then
    mkdir ${libinstall_dir}
    pushd ${libinstall_dir}
    wget -c https://ftp.gnu.org/gnu/libc/glibc-${glibc_ver}.tar.gz
	tar -xvzf glibc-${glibc_ver}.tar.gz
    popd 
fi 

if [[ ! -d "genprog-code-func-repair" ]]; then
    git clone https://github.com/pdreiter/genprog-code.git genprog-code-func-repair
	pushd genprog-code-func-repair
	git pull https://github.com/pdreiter/genprog-code.git function-based-repair
	popd
fi

if [[ ! -d "${libinstall_dir}/dietlibc" ]]; then
   mkdir -p ${libinstall_dir}/dietlibc
   pushd ${libinstall_dir}/dietlibc
   wget -c http://www.fefe.de/dietlibc/dietlibc-${dietlibc_ver}.tar.xz
   unxz dietlibc-${dietlibc_ver}.tar.xz
   tar -xvf dietlibc-${dietlibc_ver}.tar
   cd dietlibc-${dietlibc_ver}
   make 
   popd
fi
export FUNC_REPAIR_STDLIB=$(realpath stdlibc-src)
export PATH=$PATH:$(realpath ${libinstall_dir}/dietlibc/dietlibc-${dietlibc_ver}/bin-x86_64)
