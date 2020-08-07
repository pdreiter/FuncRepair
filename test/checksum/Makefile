IDIR=stdio-common stdio-common/glibc-2.28
#CC=clang-7
CC=gcc
#CFLAGS= -pie -fpie -m64 --save-temps -I$(IDIR)
I_DIRS=$(patsubst %, -I%, $(IDIR))
CFLAGS= -m32
HOOK_CFLAGS= $(CFLAGS)  -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fpic -fPIC -Wl,-shared 
#HOOK3_CFLAGS= -fPIC -Wl,-T script.ld -Wl,--whole-archive -nostdlib -nodefaultlibs -fkeep-inline-functions -fno-stack-protector -Wl,--verbose -static-libgcc -s -shared libc.a 
#HOOK3_CFLAGS= -static -fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -fkeep-inline-functions -fno-stack-protector -Wl,--start-group -lc -Wl,--end-group -static-libgcc -s -shared 
HOOK3_CFLAGS=  -fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -fkeep-inline-functions -fno-stack-protector  -shared 

FUNCREP="../../funcinsert.py"

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

hook3: 
	$(CC) $(HOOK3_CFLAGS)  patch_ex3.c -o libhook.so	

do_checksum: compile
	objdump --disassemble --all ./do_checksum > do_checksum.objdump.dis_all

do_checksum_obj:
	readelf -a -D do_checksum > do_checksum.elf
	objdump --disassemble -j .plt ./do_checksum > do_checksum.objdump.plt
	objdump --disassemble --all -j .got ./do_checksum > do_checksum.objdump.got
	echo objdump --disassemble --all -j .plt.got ./do_checksum > do_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./do_checksum > do_checksum.objdump.text

so_checksum: do_checksum hook3
	LD_LIBRARY_PATH=. $(CC) so_checksum.c -o so_checksum  libhook.so

so_checksum_obj:
	objdump --disassemble --all ./so_checksum > so_checksum.objdump.dis_all
	readelf -a -D so_checksum > so_checksum.elf
	objdump --disassemble -j .plt ./so_checksum > so_checksum.objdump.plt
	objdump --disassemble --all -j .got ./so_checksum > so_checksum.objdump.got
	objdump --disassemble --all -j .plt.got ./so_checksum > so_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./so_checksum > so_checksum.objdump.text

funcinsert: do_checksum
	$(FUNCREP) --bin do_checksum --outbin patch_do_checksum --fn patch_ex3.c checksum

funcinsert_obj:
	objdump --disassemble --all ./patch_do_checksum > patch_do_checksum.objdump.dis_all
	readelf -a -D patch_do_checksum > patch_do_checksum.elf
	objdump --disassemble -j .plt ./patch_do_checksum > patch_do_checksum.objdump.plt
	objdump --disassemble --all -j .got ./patch_do_checksum > patch_do_checksum.objdump.got
	objdump --disassemble --all -j .plt.got ./patch_do_checksum > patch_do_checksum.objdump.plt_got
	objdump --disassemble --all -j .text ./patch_do_checksum > patch_do_checksum.objdump.text


funcinsert_debug: debug funcinsert


test: funcinsert
	@echo "\nExpecting ./do_checksum to return different value than ./patch_do_checksum"
	./do_checksum 123
	./patch_do_checksum 123
	

clean:
	@echo "Removing:"
	@echo ""
	rm -rf do_checksum so_checksum *.objdump.* *.elf patch_do_checksum.* patch_do_checksum
	rm -rf libhook.so
