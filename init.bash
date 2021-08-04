#!/usr/bin/env bash

#-----------------------------------------------------
# tihs script should be source'd to allow ENV variables
# to be exported to encompassing environment
# tested with Python3 versions : 3.6.5, 3.7.3
#-----------------------------------------------------
export PRD_BASE_DIR=$(realpath .)
export IDA_BASE_DIR=$(realpath ida)
export R_LIBS=$(realpath .)/R_PACKAGES/pkgs
export PROPHET64_BASE=$(realpath .)/PROPHET/prophet-gpl
UPDATE=$1


if [[ ! -z $UPDATE ]]; then 
    git submodule update --init 
    
    if [[ -d "genprog-code-func-repair" ]]; then 
    	pushd genprog-code-func-repair
    	git checkout function-based-repair
    	popd
    fi
    
fi

# virtual environment
if which python3; then
   echo "python3 is installed"
   echo "python3 is predominantly used for the PRD infrastructure"
   echo " - requirements for python3 will be set up in the virtual env"
   echo "BUT CGC testing mechanism uses an outdated Crypto package"
   echo " which is only available on Python2.7 - Python3.3"
   echo "-- In order to support testing, please make sure these python packages" 
   echo "   are installed for Python2: "
   echo "    - pyyaml"
   echo "    - matplotlib"
   echo ""
   echo " sudo -H pip2 install pyyaml"
   echo " sudo -H pip2 install matplotlib"
   echo "    -OR- "
   echo " pip2 install pyyaml --user"
   echo " pip2 install matplotlib --user"

   
else
   echo "This infrastructure tested with 'python3' installed"
   echo "Please install 'python3'"
   echo "Ubuntu install example: sudo apt-get install python3"
   return 1
fi


if [[ ! -z "$VIRTUAL_ENV" && $VIRTUAL_ENV != "$PWD/prd-env" ]]; then
      echo "Another Virtual Environment [ $VIRTUAL_ENV ] is set up."
      echo "Please 'deactivate' and rerun to continue"
      return 1
fi
if [ -z $VIRTUAL_ENV ]; then 
   if python3 -m venv prd-env; then
      echo "python3 virtual environment is installed"
      source prd-env/bin/activate
      echo "Virtual environment @ $VIRTUAL_ENV is activated."
      echo "Installing requirements" 
	  pip install wheel
      pip install -r requirements.txt
      #pip install -c constraints.txt
   else
      echo "Need python3 virtual environment installed"
      echo "Please install 'python3-venv'"
      echo "Ubuntu install example: sudo apt-get install python3-venv"
      return 1
   fi

fi

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

# issues popped up during testing with r2ghidra - difficult to get stuff done with old version of ghidra it used
#r2_installed=$(r2 -v | egrep -c 'radare2')
#if (( $r2_installed>0 )); then
   #if [[ ! -e radare2 ]]; then 
   ## tested on git-5.4.1
   #git clone https://github.com/radare/radare2;
   #fi
   #pushd radare2; sys/install.sh; popd
   ##if [[ ! -e radare2-4.3.1 ]]; then 
   ##    wget https://github.com/radare/radare2/archive/4.3.1.tar.gz
   ##    tar xzvf 4.3.1.tar.gz
   ##    pushd radare2-4.3.1 
   ##        ./configure --prefix=/usr
   ##        make -j8
   ##        sudo make install
   ##        r2pm init
   ##    popd
   ##else
   ##    pushd radare2-4.3.1
   ##        sys/install.sh || sys/user.sh
   ##    popd
   ##fi
   ##using version r2ghidra version 5.4.0
   #r2pm update
   #r2pm install r2ghidra
   #r2pm install r2ghidra-dec
   #r2pm -ci r2ghidra
#fi

  if [[ ! -e "ghidra_10.0.1_PUBLIC_20210708" ]]; then
      wget -c https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.1_build/ghidra_10.0.1_PUBLIC_20210708.zip
      unzip ghidra_10.0.1_PUBLIC_20210708.zip
  fi
export GHIDRA_TOOL_DIR=$(realpath ./ghidra_10.0.1_PUBLIC_20210708)
export GHIDRA_HEADLESS="${GHIDRA_TOOL_DIR}/support/analyzeHeadless"

if [[ ! -d "${libinstall_dir}/dietlibc" ]]; then
   mkdir -p ${libinstall_dir}/dietlibc
   pushd ${libinstall_dir}/dietlibc
   wget -c http://www.fefe.de/dietlibc/dietlibc-${dietlibc_ver}.tar.xz
   unxz dietlibc-${dietlibc_ver}.tar.xz
   tar -xvf dietlibc-${dietlibc_ver}.tar
   cd dietlibc-${dietlibc_ver}
   $(which perl) -pi -e's#^(\#define WANT_SYSENTER)#// pdr - removing this because we want to not use the unified_syscall (BREAKS STUFF)\n//$1#' dietfeatures.h

   make 
   make i386
   #make x32
   popd
fi
#export DIETX32PATH=$(realpath ${libinstall_dir}/dietlibc/dietlibc-${dietlibc_ver}/bin-x32)
export DIET32PATH=$(realpath ${libinstall_dir}/dietlibc/dietlibc-${dietlibc_ver}/bin-i386)
export DIET64PATH=$(realpath ${libinstall_dir}/dietlibc/dietlibc-${dietlibc_ver}/bin-x86_64)
#CMake adds double quotes around "$DIET32PATH/diet clang" which the shell interpreter barfs on
# this is a workaround 
#echo -e "#!/usr/bin/env bash\n$DIETX32PATH/diet \$(which gcc) -nostdinc \$@" > ${DIETX32PATH}/diet_gcc
#echo -e "#!/usr/bin/env bash\n$DIETX32PATH/diet \$(which g++) -nostdinc \$@" > ${DIETX32PATH}/diet_g++
#echo -e "#!/usr/bin/env bash\n$DIETX32PATH/diet \$(which clang) -nostdinc \$@" > ${DIETX32PATH}/diet_clang
#echo -e "#!/usr/bin/env bash\n$DIETX32PATH/diet \$(which clang++) -nostdinc \$@" > ${DIETX32PATH}/diet_clang++
#chmod +x ${DIETX32PATH}/diet_gcc ${DIETX32PATH}/diet_g++ ${DIETX32PATH}/diet_clang ${DIETX32PATH}/diet_clang++
[[ ! -e ${DIET32PATH}/diet_gcc ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/gcc -nostdinc \$@ " > ${DIET32PATH}/diet_gcc
[[ ! -e ${DIET32PATH}/diet_gcc-8 ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/gcc-8 -nostdinc \$@ " > ${DIET32PATH}/diet_gcc-8
[[ ! -e ${DIET32PATH}/diet_g++ ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/g++ -fpermissive -nostdlib -nostdinc \$@ -I$DIET32PATH/../include" > ${DIET32PATH}/diet_g++
[[ ! -e ${DIET32PATH}/diet_g++-8 ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/g++-8 -fpermissive -nostdlib -nostdinc \$@ -I$DIET32PATH/../include" > ${DIET32PATH}/diet_g++-8
[[ ! -e ${DIET32PATH}/diet_clang ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/clang -nostdinc \$@ " > ${DIET32PATH}/diet_clang
[[ ! -e ${DIET32PATH}/diet_clang++ ]] && echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet /usr/bin/clang++ -fpermissive -nostdlib -nostdinc \$@ -I$DIET32PATH/../include" > ${DIET32PATH}/diet_clang++
chmod +x ${DIET32PATH}/diet_gcc* ${DIET32PATH}/diet_g++* ${DIET32PATH}/diet_clang ${DIET32PATH}/diet_clang++
if [[ ! -z $ENABLED_64 ]] ; then
[[ ! -e ${DIET64PATH}/diet_gcc ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/gcc -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_gcc
[[ ! -e ${DIET64PATH}/diet_gcc-8 ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/gcc-8 -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_gcc-8
[[ ! -e ${DIET64PATH}/diet_g++ ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/g++ -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_g++
[[ ! -e ${DIET64PATH}/diet_g++-8 ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/g++-8 -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_g++-8
[[ ! -e ${DIET64PATH}/diet_clang ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/clang -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_clang
[[ ! -e ${DIET64PATH}/diet_clang++ ]] && echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet /usr/bin/clang++ -nostdinc \$@ -I$DIET64PATH/../include" > ${DIET64PATH}/diet_clang++
chmod +x ${DIET64PATH}/diet_gcc* ${DIET64PATH}/diet_g++* ${DIET64PATH}/diet_clang ${DIET64PATH}/diet_clang++
fi

export FUNC_REPAIR_STDLIB=$(realpath stdlibc-src)
export PATH=$PATH:$(realpath ${libinstall_dir}/dietlibc/dietlibc-${dietlibc_ver}/bin-x86_64)

export PRD_GENPROG_DIR=${PRD_BASE_DIR}/genprog-code-func-repair
export PRD_GENPROGSRC_DIR=${PRD_GENPROG_DIR}/src

export CGC_BASE_DIR=${PRD_BASE_DIR}/cgc
[[ ! -e ${CGC_BASE_DIR} ]] && mkdir -p ${CGC_BASE_DIR}


#export DESTDIR=${CGC_BASE_DIR}/cgc-build
#[[ ! -d "${DESTDIR}" ]] && mkdir -p ${DESTDIR}

# Construct pdreiter's version of CGC environment
pushd ${CGC_BASE_DIR}

export CGC_CB_DIR=${CGC_BASE_DIR}/cb-multios

PY2_PATH=${CGC_BASE_DIR}/poll-generator/lib
if [[ -z $PYTHONPATH ]]; then
export PYTHONPATH=$PY2_PATH
else
export PYTHONPATH=$PYTHONPATH:$PY2_PATH
fi

popd

