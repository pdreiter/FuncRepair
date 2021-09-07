 #!/usr/bin/env bash
 # need GCC-4.8

 basedir=$(realpath -- $PWD)
 if [[ ! -d llvm-3.6.2 ]]; then 
 mkdir llvm-3.6.2
 cd llvm-3.6.2
 wget https://releases.llvm.org/3.6.2/llvm-3.6.2.src.tar.xz
 tar xf llvm-3.6.2.src.tar.xz
 mv llvm-3.6.2.src llvm
# NEED TO APPLY PATCHES HERE

 wget https://releases.llvm.org/3.6.2/cfe-3.6.2.src.tar.xz
 tar xf cfe-3.6.2.src.tar.xz
 mv cfe-3.6.2.src llvm/tools/clang
# NEED TO APPLY PATCHES HERE

 wget https://releases.llvm.org/3.6.2/compiler-rt-3.6.2.src.tar.xz
 tar xf compiler-rt-3.6.2.src.tar.xz
 mv compiler-rt-3.6.2.src llvm/projects/compiler-rt
# NEED TO APPLY PATCHES HERE
 mkdir build; cd build
 cmake \
	 -DCMAKE_C_COMPILER='gcc-4.8' \
	 -DCMAKE_CXX_COMPILER='g++-4.8' \
	 -DCMAKE_INSTALL_PREFIX=$(realpath ../tools) \
	 -DCMAKE_C_FLAGS=" -Wno-unused-function " \
	 -DCMAKE_CXX_FLAGS=" -Wno-unused-function "  \
	 -DCMAKE_CPP_FLAGS=" -Wno-unused-function " \
	 ../llvm/
 make
 make install
 cd ..
 #CC=gcc-4.8 CXX=g++-4.8 ../llvm/configure -v --prefix=$(realpath ../tools) --with-gcc-toolchain=/usr/lib/gcc/x86_64-linux-gnu/4.8 --disable-bindings

 mkdir build32; cd build32
 mkdir -p ../tools
 cmake -DLLVM_BUILD_32_BITS=ON \
	 -DCMAKE_C_COMPILER='gcc-4.8' \
	 -DCMAKE_CXX_COMPILER='g++-4.8' \
	 -DCMAKE_INSTALL_PREFIX=$(realpath ../tools/32) \
	 -DCMAKE_C_FLAGS="-m32 -Wno-unused-function " \
	 -DCMAKE_CXX_FLAGS="-m32 -Wno-unused-function "  \
	 -DCMAKE_CPP_FLAGS="-m32 -Wno-unused-function " \
	 ../llvm/
 #CC=gcc-4.8 CXX=g++-4.8 ../llvm/configure -v --prefix=$(realpath ../tools) --with-gcc-toolchain=/usr/lib/gcc/x86_64-linux-gnu/4.8 --disable-bindings
 make
 make install
 cd ../tools/32; 
 echo "export PATH=\$PATH:$PWD" > $basedir/prophet_setup.bash
 export PATH=$PATH:$PWD
fi
cd $basedir
source prophet_setup.bash
[[ ! -d PROPHET ]] &&  mkdir PROPHET
 cd PROPHET

 [[ ! -e README.html ]] && wget http://www.cs.toronto.edu/~fanl/program_repair/prophet-rep/README.html
 # please read fanl's README.html
 # pre-requisites:
 #  + llvm-3.6.2
 #  + gcc<=4.9
[[ ! -d prophet-gpl ]] && ( wget http://www.cs.toronto.edu/~fanl/program_repair/prophet-rep/prophet-0.1-src.tar.gz; \
	tar -xvzf prophet-0.1-src.tar.gz >& /dev/null )

# NEED TO APPLY PATCHES HERE

 perl -pie 's/-Werror(\s*)/-Wno-unused-function$1/' prophet-gpl/configure.ac

 cp -r prophet-gpl prophet-gpl-32
 cd prophet-gpl
 autoreconf --install
  CC=gcc-4.8 CXX=g++-4.8 ./configure -v --with-sysroot=/usr/lib/gcc/x86_64-linux-gnu/4.8.5
  make
  echo "export PROPHET64_BASE=$PWD" >> $basedir/prophet_setup.bash
 cd ..
 cd prophet-gpl-32
 autoreconf --install
 FLAGS='-m32 -Wno-unused-function -g -O2 -fno-rtti'
  CC=gcc-4.8 CXX=g++-4.8 ./configure -v --with-sysroot=/usr/lib/gcc/x86_64-linux-gnu/4.8.5 CFLAGS="$FLAGS" CPPFLAGS="$FLAGS" CXXFLAGS="$FLAGS"
  make
  echo "export PROPHET32_BASE=$PWD" >> $basedir/prophet_setup.bash
 cd ..
