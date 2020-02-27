IDIR=stdio-common stdio-common/glibc-2.28
#CC=clang-7
CC=gcc
#CFLAGS= -pie -fpie -m64 --save-temps -I$(IDIR)
I_DIRS=$(patsubst %, -I%, $(IDIR))
CFLAGS=
HOOK_CFLAGS=-Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared 

FUNCREP="../../funcrepair.py"

#SDIR=src
#ODIR=obj
#$(shell mkdir -p $(ODIR))

#_DEPS = testbed.h
#DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

#_OBJ = example_2.o testbed.o
#OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all:compile
debug: 
	$(CC) -g -o do_checksum do_checksum.c $(CFLAGS) 

compile: 
	$(CC) -g -o do_checksum do_checksum.c $(CFLAGS) 

#$(ODIR)/%.o: $(SDIR)/%.c 
#	$(CC) -c -o $@ $< $(CFLAGS)
#
#example_2.bin: $(OBJ)
#	$(CC) -o $@ $^ $(CFLAGS)

hook: 
	$(CC) $(HOOK_CFLAGS) $(I_DIRS) patch_ex2.c -o libhook.so	

do_checksum: compile
	objdump --disassemble --all ./do_checksum > do_checksum.objdump.dis_all
	readelf -a -D do_checksum > do_checksum.elf
	objdump --disassemble -j .plt ./do_checksum > do_checksum.objdump.plt
	objdump --disassemble --all -j .got ./do_checksum > do_checksum.objdump.got
	echo objdump --disassemble --all -j .plt.got ./do_checksum > do_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./do_checksum > do_checksum.objdump.text

so_checksum: do_checksum hook
	LD_LIBRARY_PATH=. $(CC) so_checksum.c -o so_checksum  libhook.so
	objdump --disassemble --all ./so_checksum > so_checksum.objdump.dis_all
	readelf -a -D so_checksum > so_checksum.elf
	objdump --disassemble -j .plt ./so_checksum > so_checksum.objdump.plt
	objdump --disassemble --all -j .got ./so_checksum > so_checksum.objdump.got
	objdump --disassemble --all -j .plt.got ./so_checksum > so_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./so_checksum > so_checksum.objdump.text

funcrepair: do_checksum
	$(FUNCREP) --bin do_checksum --outbin patch_do_checksum --fn patch_ex2.c checksum
	objdump --disassemble --all ./patch_do_checksum > patch_do_checksum.objdump.dis_all
	readelf -a -D patch_do_checksum > patch_do_checksum.elf
	objdump --disassemble -j .plt ./patch_do_checksum > patch_do_checksum.objdump.plt
	objdump --disassemble --all -j .got ./patch_do_checksum > patch_do_checksum.objdump.got
	objdump --disassemble --all -j .plt.got ./patch_do_checksum > patch_do_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./patch_do_checksum > patch_do_checksum.objdump.text


funcrepair_debug: debug funcrepair


test: funcrepair
	@echo "\nExpecting ./do_checksum to return different value than ./patch_do_checksum"
	./do_checksum 123
	./patch_do_checksum 123
	

clean:
	@echo "Removing:"
	ls do_checksum so_checksum *.objdump.* *.elf patch_do_checksum.* patch_do_checksum
	@echo ""
	rm -rf do_checksum so_checksum *.objdump.* *.elf patch_do_checksum.* patch_do_checksum
