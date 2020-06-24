#!/usr/bin/env bash

#-----------------------------------------------------
# tihs script should be source'd to allow ENV variables
# to be exported to encompassing environment
#-----------------------------------------------------
export PRD_BASE_DIR=$(realpath .)

# virtual environment
if which python3.6; then
   echo "python3.6 is installed"
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
   
else
   echo "This infrastructure tested with 'python3.6' installed"
   echo "Please install 'python3.6'"
   echo "Ubuntu install example: sudo apt-get install python3.6"
   return 1
fi


if [[ ! -z "$VIRTUAL_ENV" && $VIRTUAL_ENV != "$PWD/prd-env" ]]; then
      echo "Another Virtual Environment [ $VIRTUAL_ENV ] is set up."
      echo "Please 'deactivate' and rerun to continue"
      return 1
fi
if [ -z $VIRTUAL_ENV ]; then 
   if python3.6 -m venv prd-env; then
      echo "python3 virtual environment is installed"
      source prd-env/bin/activate
      echo "Virtual environment @ $VIRTUAL_ENV is activated."
      echo "Installing requirements" 
      pip install -f requirements.txt
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

if [[ ! -d "genprog-code-func-repair" ]]; then
    git clone https://github.com/pdreiter/genprog-code-prd.git genprog-code-func-repair
	pushd genprog-code-func-repair
	git pull https://github.com/pdreiter/genprog-code-prd.git function-based-repair
	popd
fi

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
echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet \$(which gcc) -nostdinc \$@" > ${DIET32PATH}/diet_gcc
echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet \$(which g++) -nostdinc \$@" > ${DIET32PATH}/diet_g++
echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet \$(which clang) -nostdinc \$@" > ${DIET32PATH}/diet_clang
echo -e "#!/usr/bin/env bash\n$DIET32PATH/diet \$(which clang++) -nostdinc \$@" > ${DIET32PATH}/diet_clang++
chmod +x ${DIET32PATH}/diet_gcc ${DIET32PATH}/diet_g++ ${DIET32PATH}/diet_clang ${DIET32PATH}/diet_clang++
echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet \$(which gcc) -nostdinc \$@" > ${DIET64PATH}/diet_gcc
echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet \$(which g++) -nostdinc \$@" > ${DIET64PATH}/diet_g++
echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet \$(which clang) -nostdinc \$@" > ${DIET64PATH}/diet_clang
echo -e "#!/usr/bin/env bash\n$DIET64PATH/diet \$(which clang++) -nostdinc \$@" > ${DIET64PATH}/diet_clang++
chmod +x ${DIET64PATH}/diet_gcc ${DIET64PATH}/diet_g++ ${DIET64PATH}/diet_clang ${DIET64PATH}/diet_clang++

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

# the following are no longer needed because going with cb-multios
#[[ ! -d "${CGC_BASE_DIR}/samples" ]] && \
#git clone https://github.com/pdreiter/samples.git
#[[ ! -d "${CGC_BASE_DIR}/cgc2elf" ]] && \
#  git clone https://github.com/pdreiter/cgc2elf.git
#[[ ! -d "${CGC_BASE_DIR}/cb-testing" ]] && \
#  git clone https://github.com/pdreiter/cb-testing.git
#[[ ! -d "${CGC_BASE_DIR}/libcgc" ]] && \
#  git clone https://github.com/pdreiter/libcgc.git
#[[ ! -d "${CGC_BASE_DIR}/poll-generator" ]] && \
#  git clone https://github.com/pdreiter/poll-generator.git
#[[ ! -d "${CGC_BASE_DIR}/cgc-release-documentation" ]] && \
#  git clone https://github.com/pdreiter/cgc-release-documentation.git
#[[ ! -d "${CGC_BASE_DIR}/pov-xml2c" ]] && \
#  git clone https://github.com/pdreiter/pov-xml2c.git

[[ ! -d "${CGC_BASE_DIR}/cb-multios" ]] && \
  git clone https://github.com/pdreiter/cb-multios-prd.git cb-multios && \
  pushd cb-multios && git checkout genprog_afr_prd && popd

export CGC_CB_DIR=${CGC_BASE_DIR}/cb-multios

PY2_PATH=${CGC_BASE_DIR}/poll-generator/lib
if [[ -z $PYTHONPATH ]]; then
export PYTHONPATH=$PY2_PATH
else
export PYTHONPATH=$PYTHONPATH:$PY2_PATH
fi

popd

