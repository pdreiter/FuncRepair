IDIR=include
IDIRS=$(patsubst %, -I%, $(IDIR))
CC=diet gcc
CFLAGS= -pie -fpie -m64 -I$(IDIR)
LIBDIR=./static_libs
LIBDIRS=$(patsubst %, -L%, $(LIBDIR))

#--------
# the following HOOK_CFLAGS gives this error:
#/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/8/libgcc_eh.a(unwind-dw2-fde-dip.o): in function `_Unwind_Find_FDE':
#(.text+0x19ed): undefined reference to `dl_iterate_phdr'
#collect2: error: ld returned 1 exit status
#
#HOOK_CFLAGS= -fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -nostartfiles -fkeep-static-functions -static-libgcc -l:libgcc.a -l:libc.a -l:libgcc_eh.a -Wl,-N -fno-plt $(IDIRS) 

# the libgcc_eh.a is the static version of the libgcc_s.so.* library, which
# contains the following:
#
# running into segfault issues with the following HOOK_CFLAGS - segfaulting in puts:
#HOOK_CFLAGS= -fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -nostartfiles -fkeep-static-functions -static -static-libgcc -Wl,-N -fno-plt $(IDIRS) $(HOOK_LIB_DEPEND)
#--------

# STATIC LINKING DOES NOT WORK:
# gcc --save-temps decompiled_function.c -o libhook.so -fPIE -fPIC -nostdlib -nodefaultlibs -Wl,-N -nostartfiles -fno-plt -fkeep-static-functions  -L./static_libs/glibc-2.31-static -static -static-libgcc  -Iinclude -l:libgcc.a -l:libc.a -l:libgcc_eh.a -l:libc.a -l:libgcc.a
# Basically, the following doesn't work, because I don't want the entire libc, 
# i just want a subset of the glibc functionality that I'm specifically calling
#HOOK_LIB_DEPEND= -L./static_libs/glibc-2.31-static -l:libgcc.a -l:libc.a -l:libgcc_eh.a -l:libc.a -l:libgcc.a 
HOOK_LIB_DEPEND= 
# instead, let's just use the barebones static stdio functions I made 
# 
# THE static library built from the glibc's socket DOES NOT WORK
#
#HOOK_LIB_DEPEND=-Wl,--whole-archive ./static_libs/libstdio_static.a ./static_libs/libsocket_glibc.a -Wl,--no-whole-archive -Wl,--version-script ./static_libs/libc.map
# Using static library from external standalone socket library
#HOOK_LIB_DEPEND=-Wl,--whole-archive ./static_libs/libstdio_static.a ./static_libs/libsocket.a -Wl,--no-whole-archive  -shared

#HOOK_LINKER_FLAGS= -Wl,-T script.ld -nostdlib -nodefaultlibs -nostartfiles -Wl,-N -fno-plt
#HOOK_LINKER_FLAGS= -Wl,-T script.ld -nostdlib -nodefaultlibs -Wl,-N
HOOK_LINKER_FLAGS= -Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,text,-z,norelro,-T,script.ld
HOOK_CFLAGS= -fPIC -static-pie $(HOOK_LINKER_FLAGS) $(IDIRS) $(HOOK_LIB_DEPEND)

# maybe try these flags if -static-pie doesn't work:
#-Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,text

#TEST_CFLAGS= -fPIC -nostdlib -nodefaultlibs -fkeep-static-functions -L ./static_libs -static -static-libgcc $(IDIRS) $(HOOK_LIB_DEPEND) --entry main
TEST_CFLAGS= -Wl,-rpath,.

FUNCREP="../../funcinsert.py"



SDIR=src
ODIR=obj
$(shell mkdir -p $(ODIR))

_DEPS = testbed.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = example_2.o testbed.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

#	$(CC) $(HOOK_CFLAGS) --save-temps decompiled_function.c -o libhook.so	$(HOOK_LIB_DEPEND)
hook: 
	$(CC) --save-temps decompiled_function.c -o libhook.so $(HOOK_CFLAGS)

test:
	$(CC) -L. testmain.c -lhook -o test_server $(TEST_CFLAGS)

funcinsert: hook
	$(FUNCREP) --do-not-override-so --bin example_2.bin --outbin example_2.trampoline.bin --fn decompiled_function.c runServer

funcinsert_coverage:
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn coverage.c runServer

funcinsert_sanity:
	$(FUNCREP) --bin example_2.bin --outbin example_2.trampoline.bin --fn repair.sanity.c runServer


all: hook_inserted_c
	$(CC) -o example_2.bin src/example_2.c $(CFLAGS) -I$(IDIR)

$(ODIR)/%.o: $(SDIR)/%.c 
	$(CC) -c -o $@ $< $(CFLAGS)

example_2.bin: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -rf $(ODIR)
	rm -rf example_2.*
