 #!/usr/bin/env bash
 mkdir PROPHET
 cd PROPHET
 wget http://www.cs.toronto.edu/~fanl/program_repair/prophet-rep/README.html
 # please read fanl's README.html
 # pre-requisites:
 #  + llvm-3.6.2
 #  + gcc<=4.9
 wget http://www.cs.toronto.edu/~fanl/program_repair/prophet-rep/prophet-0.1-src.tar.gz
 tar -xvzf prophet-0.1-src.tar.gz >& /dev/null
 cd prophet-gpl
 autoreconf --install
 ./configure CC=$(realpath llvm-3.6.2/tools/bin/clang) -v
 cd ..
