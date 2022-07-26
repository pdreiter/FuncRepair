## How to run End-to-End BinREPARED on CGC:


1. Update cgc/cb-multios git submodule (if not populated)
   (expecting remaining steps to be run in `$CGC_CB_DIR`
2. Build CGC Binaries: `$PRD_BASE_DIR/tools/cb-multios/build.sh -v`
3. Obtain test content for CGC Binaries (polls.tgz for exact duplication)
   or ./genpolls.sh from cb-multios
4. Initialize CGC Testing environment: 
    `$PRD_BASE_DIR/tools/cgc_test_setup.bash`-rundir=cgc-testrun <CGC CBS>`
5. Run end-to-end script for CB:
    `$PRD_BASE_DIR/tools/binrepared_e2e.bash <CB> <destdir>`
6. Run APR scripts for CB:
    `$destdir/apr/scripts/APR.gp_reg.bash`(GenProg)
    `$destdir/apr/scripts/APR.p_reg.bash` (prophet)

NOTE: While GenProg can be run in parallel, Prophet cannot due to tmpdir conflicts that can occur.


## How to recompile decompiled image with GCC:

	gcc-8 -m32 <DEFINES> -fno-stack-protector -nostdlib -nodefaultlibs -fpic -fPIC -static-pie -shared -z now --save-temps -c <BIN>_recomp.c -o depobj/<BIN>_recomp.o <INCLUDES>
	gcc-8 -m32 <DEFINES> -fno-stack-protector -nostdlib -nodefaultlibs -fpic -fPIC -static-pie -shared -z now -Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,now,-z,norelro,-T,script.ld,-static -Ilibsrc -o libhook.so depobj/<BIN>_recomp.o

- Example GCC-based Makefile (requires `prd_includes.mk`)
	- `./Makefile.prd_gcc`

## How to collect CGFL (Function-spectral):

1. Collect information about `<EXE>`
	./screen_small_functions.py --exe <EXE> --json-out <OUT>/info.json
2. Generate Function-spectra from tests by prepending testing with:
	/usr/bin/valgrind --tool=callgrind --log-file=$outdir/$cur_case.cgfl.log --callgrind-out-file=$outdir/$cur_case.cg.out
	- `$cur_case` should be unique per test case with positive tests differentiable from negative
	- `$outdir` location for valgrind output 
3. Process Function-spectra: `cgfl_finish.py`
	1. Annotate callgrind content
	2. Screen function list by byte size (or instruction size)
	3. Calculate suspiciousness metrics
	4. Generate RankAggreg R-script
	./prdtools/cgfl_finish.py --top-k-percent <TOP_K=0.35> --r-out <RSCRIPT_OUTDIR> --exe <EXE> --lib <LIBSOS> --src <SRC_DIR> --results $outdir --byte-min <BYTE_MIN_VAL>
4. Aggregate ranks through RankAggreg R-script:
	<RSCRIPT_OUTDIR>/<EXE>.r

## PRD Pre-requisities

1. Partial Recompilation
    - gcc>=8.4.0
    - objdump
    - nm
2. Binary Rewriting
    - Python3
    - LIEF
3. Decompilation
    - Hex-Rays license

## PRD tested configuration

    -  Ubuntu 19.04/18.04
    -  gcc-8.4.0
    -  GLIBC 2.29\* 
    -  Binutils 2.32\*
    -  Python 3.7

\* will require customization for llvm-3.6.2

## DONE
