#!/usr/bin/env bash

set -e
# Root cb-multios directory
DIR=${CGC_CB_DIR}
TOOLS="$DIR/tools"
NINJA_ENABLED=0

# Install necessary python packages
if ! /usr/bin/env python2 -c "import xlsxwriter; import Crypto" 2>/dev/null; then
    echo "Please install required python2 packages" >&2
    echo "  $ sudo pip install xlsxwriter pycrypto" >&2
    exit 1
fi


# Honor CC and CXX environment variables, default to clang otherwise
CC=${CC:-gcc}
CXX=${CXX:-g++}
BUILD=32
DIETLIBC=0
VERBOSE=0
STATICPIE="OFF"
BOTHLIBS="OFF"
(( $# > 0 )) && \
for i in "$@"; do 
echo "$i"
[[ "$i" == "-v" ]] && VERBOSE=1 && echo "Enabling verbose build"; \
done

echo "Creating build directory"
mkdir -p ${DIR}/build${BUILD}
ln -sfn ${DIR}/build${BUILD} ${DIR}/build
cd ${DIR}/build${BUILD}

echo "Creating Makefiles"
CMAKE_OPTS="${CMAKE_OPTS} -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"

CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_C_COMPILER=$CC"
CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_ASM_COMPILER=$CC"
CMAKE_OPTS="$CMAKE_OPTS -DCMAKE_CXX_COMPILER=$CXX"

(( $VERBOSE == 1 )) && CMAKE_OPTS="${CMAKE_OPTS} -DCMAKE_VERBOSE_MAKEFILE=ON"
(( $VERBOSE == 0 )) && CMAKE_OPTS="${CMAKE_OPTS} -DCMAKE_VERBOSE_MAKEFILE=OFF"

LINK=${LINK:-SHARED}
case $LINK in
    SHARED) CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_LIBS=OFF";;
    STATIC) CMAKE_OPTS="$CMAKE_OPTS -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON";;
esac

# Prefer ninja over make, if it is available
if $NINJA_ENABLED && which ninja 2>&1 >/dev/null; then
  CMAKE_OPTS="-G Ninja $CMAKE_OPTS"
  BUILD_FLAGS=
else
  BUILD_FLAGS=
fi

# this is the default build
cmake $CMAKE_OPTS ..

cmake --build . $BUILD_FLAGS

echo -e "Built using these commands:"
echo -e "\t%>cmake $CMAKE_OPTS .. "
echo -e "\t%>cmake --build . $BUILD_FLAGS"

