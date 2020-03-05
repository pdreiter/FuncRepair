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

hook: 
	$(CC) $(HOOK_CFLAGS) decompiled_function.c -o libhook.so	

funcinsert:
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn decompiled_function.c runCheckSum


all:
	$(CC) -o example_2.bin src/example_2.c $(CFLAGS) -I$(IDIR)

$(ODIR)/%.o: $(SDIR)/%.c 
	$(CC) -c -o $@ $< $(CFLAGS)

example_2.bin: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(ODIR)
	rm -rf example_2.*
