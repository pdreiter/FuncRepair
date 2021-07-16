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
	./cgfl_finish.py --top-k-percent <TOP_K=0.35> --r-out <RSCRIPT_OUTDIR> --exe <EXE> --lib <LIBSOS> --src <SRC_DIR> --results $outdir --byte-min <BYTE_MIN_VAL>
4. Aggregate ranks through RankAggreg R-script:
	<RSCRIPT_OUTDIR>/<EXE>.r

## DONE
