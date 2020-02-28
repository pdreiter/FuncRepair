#!/bin/bash

if [[ ! -d "stdlib-src/glibc-2.28" ]]; then
    mkdir stdlib-src
    pushd stdlib-src
    wget -c https://ftp.gnu.org/gnu/libc/glibc-2.28.tar.gz
	tar -xvzf glibc-2.28.tar.gz
    popd 
fi 

if [[ ! -d "genprog-code-func-repair" ]]; then
    git clone https://github.com/pdreiter/genprog-code.git genprog-code-func-repair
	pushd genprog-code-func-repair
	git pull https://github.com/pdreiter/genprog-code.git function-based-repair
	popd
fi
