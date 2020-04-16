IDIR=include
CC=gcc
CFLAGS= -pie -fpie -m64 -I$(IDIR)
HOOK_CFLAGS=  -fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -fkeep-inline-functions -I$(IDIR) -fno-stack-protector  -shared 

FUNCREP="../../../../funcinsert.py"


SDIR=src
ODIR=obj
$(shell mkdir -p $(ODIR))

_DEPS = testbed.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = example_2.o testbed.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

preprocess_insertion:
	echo '#include "stdlibc-src/stdio_static.c"' > decompiled_function_inserted_c.c
	cat decompiled_function.c >> decompiled_function_inserted_c.c

hook_inserted_h: 
	$(CC) $(HOOK_CFLAGS) -fPIE -fno-jump-tables -fno-plt -static -Istdlibc-src  decompiled_function_inserted.c stdlibc-src/stdio_static.c -o libhook.so	

hook_inserted_c: preprocess_insertion
	$(CC) $(HOOK_CFLAGS) -Istdlibc-src --save-temps decompiled_function_inserted_c.c -o libhook.so	

hook: 
	$(CC) $(HOOK_CFLAGS) --save-temps decompiled_function.c -o libhook.so	

funcinsert: preprocess_insertion
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn decompiled_function.c runCheckSum
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline_print.bin --fn decompiled_function_inserted_c.c runCheckSum

funcinsert_coverage:
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn coverage.c runCheckSum

funcinsert_sanity:
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn repair.sanity.c runCheckSum


all: hook_inserted_c
	$(CC) -o example_2.bin src/example_2.c $(CFLAGS) -I$(IDIR)

$(ODIR)/%.o: $(SDIR)/%.c 
	$(CC) -c -o $@ $< $(CFLAGS)

example_2.bin: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(ODIR)
	rm -rf example_2.*
