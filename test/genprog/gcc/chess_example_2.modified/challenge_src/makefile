IDIR=include
CC=clang-7
CFLAGS= -pie -fpie -m64 -I$(IDIR)

SDIR=src
ODIR=obj

_DEPS = testbed.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = example_2.o testbed.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

example_2.bin: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(ODIR)/*.o
