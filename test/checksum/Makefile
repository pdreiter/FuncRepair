IDIR=include
#CC=clang-7
CC=gcc
#CFLAGS= -pie -fpie -m64 --save-temps -I$(IDIR)
CFLAGS= 

FUNCREP="../../funcrepair.py"

#SDIR=src
#ODIR=obj
#$(shell mkdir -p $(ODIR))

#_DEPS = testbed.h
#DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

#_OBJ = example_2.o testbed.o
#OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all:compile
compile:
	$(CC) -o do_checksum do_checksum.c $(CFLAGS) -I$(IDIR)

#$(ODIR)/%.o: $(SDIR)/%.c 
#	$(CC) -c -o $@ $< $(CFLAGS)
#
#example_2.bin: $(OBJ)
#	$(CC) -o $@ $^ $(CFLAGS)

funcrepair: compile
	$(FUNCREP) --bin do_checksum --outbin patched_do.bin --fn patch_ex2.c checksum

test: funcrepair
	echo "Expecting ./do_checksum to return different value than ./patched_do.bin"
	./do_checksum 123
	./patched_do.bin 123
	

clean:
	rm -rf do_checksum
