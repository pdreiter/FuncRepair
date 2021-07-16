# PRD-enabled Prophet
## diff patches for enabling PRD for Prophet
diff patches are located in patches
recommendation is to do the following:
1. Install/build prerequisites (LLVM+CLANG==3.6.2, GCC<=4.9). 
2. download latest Prophet tarball 
3. build and test Prophet (you can use Prophet-provided examples or CodeFlaws <=recommend)
4. apply PRD diff patches to prophet-gpl source from patches/ subdir (some patches contain changes that enable GLIBC >=2.28 support, updated git paths)
   - make sure that tools/[tp]clang.py are updated in wrap/


## CAVEATS
- Prophet requires LLVM version 3.6.2 which does not play well with modern GLIBC headers. 
- Prophet does not allow for parallelism - temporary directories and files are used and deleted indiscriminantly
- Please note that Prophet manipulates the PATH env variable prepending its tools directory
If you have full paths in your Makefiles/build tool invocations, this will be an issue. I worked around this by generating a custom Makefile (i.e. Makefile.prophet) that basically does what Prophet's pclang.py does, bypassing Prophet's tools

## Full-source code Prophet APR CAVEATS
The following only pertains to full-source Prophet APR tool with cb-multios CGC CBs, not Prophet PRD APR
### 32b and 64b support
Prophet build doesn't naturally generate both 32b and 64b libraries
If you don't reuse CGC's CMake, this isn't a problem. However, cmake compiles a 64b 
test executable to make sure the compiler works and then the CGC CBs are 32b.
Because the build process was not changed, w/a was implemented 
that dynamically changed path between 32b Prophet and 64b Prophet libraries.
These libpaths need to be managed in the compile scripts - example scripts expect this path:
64b Prophet @ prophet-gpl/  
32b Prophet @ prophet-gpl/32/  

### PRD+Prophet
The CGC/PRD implementation of Prophet uses the 64b libraries (e.g. libprofiler.so.0), but conditionally compiles the profiling and runtime components with partial recompilation (e.g. \_prophet\_profile.cpp, \_test\_runtime.cpp, et al.). 
You can see both in the content of `Makefile.prophet`.

## External Repositories required
[FuncRepair](https://github.com/pdreiter/FuncRepair) : this repo is a submodule of `FuncRepair` and contains initialization content of related tools (GenProg, dietlibc, etc.) as well as the binary rewriting script used in the _PRD_ framework `funcinsert.py`

## Environmental Variables required
`PROPHET64_BASE` : Needs to be set to the base directory of the 64b version of Prophet
`CGC_CB_DIR`     : This env variable points to the root of this repository. When `FuncRepair` git repo is cloned (this repo is a submodule), `init.bash` sets this variable.


