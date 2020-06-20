#!/usr/bin/env python3
"""
program: {0}
purpose: extract set of functions from binary and patch with external input file
         currently developed with assumption that functions being patched exist in input binary image
         and not an external dynamic shared object/library
"""

import lief
import argparse
import os,copy
from datetime import datetime
dateinfo=datetime.now().strftime("%d%m%Y%I%M%S")

default_cwd=os.path.realpath(".")
default_src=default_cwd
debug = False
just_seg = False
no_date=False
default_log = "{}/funcinsert.debug.log".format(default_cwd)
#default_cflags="-fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -nostartfiles -fkeep-static-functions -static -static-libgcc -Wl,-N -fno-plt"
#default_hook_lib_depend="-l:libgcc.a -l:libc.a -l:libgcc_eh.a -l:libc.a -l:libgcc.a" 
#default_hook_cflags=" {} {} ".format(default_cflags,default_hook_lib_depend)
default_cflags="-static-pie -fPIC -Wl,-pie,--no-dynamic-linker,--eh-frame-hdr,-z,text,-z,norelro,-T,script.ld"
default_hook_cflags=" {} ".format(default_cflags)
RENAME_FUNCTION=False

#default_hook_cflags='-fPIC -nostdlib -nodefaultlibs -fno-builtin -static -fno-plt -L ./static_libs -shared'
override_so = True
with open(default_log,"w") as f:
    print("HELLO",file=f,flush=True)
    f.close()

hook_filename="libhook.so"

def dprint(*args, **kwargs):
    if debug:
       print(*args, **kwargs)
    with open(default_log,"a") as f:
       #print(*args,**kwargs,file=f,flush=True)
       print(*args,file=f,flush=True)

def parse_arguments():
    parser = argparse.ArgumentParser(description=\
             "Create new binary image from input binary image where subset of functions are swapped with external functions")
    parser.add_argument('funcs',metavar='Fn',type=str,nargs='+',
                        help='a function to replace in Input binary image')
    parser.add_argument('--bin',dest='infile',action='store',
                        help='Input binary image')
    parser.add_argument('--outbin',dest='outfile',action='store',
                        help='Output binary image, where funcs from Input binary image have been hot swapped with patch file functions')
    parser.add_argument('--fn',dest='patchfile',action='store',
                        help='Input containing external functions for swapping')
    parser.add_argument('--hook-cflags',dest='cflags', action='store', default=default_hook_cflags,
                        help='Specify compiler flags for generating libhook.so')
    parser.add_argument('--date',dest='nodate', action='store_const', const=False,
                        default=True,
                        help='Append date info on the libhook.so filename (Default behavior does not append date unless "--genprog" is specified)')
    parser.add_argument('--genprog',dest='genprog', action='store_const', const=True,
                        default=False,
                        help='Runs in genprog mode, where intermediate files are deleted after generation.')
    parser.add_argument('--nodietlibc',dest='dietlibc', action='store_const', const=False,
                        default=True,
                        help='Do not use "dietlibc" (default is to use "dietlibc")')
    parser.add_argument('--compiler',dest='compiler', action='store', default='gcc',
                        help='Specify compiler (default is "gcc")')
    #parser.add_argument('--clang',dest='compiler', action='store_const', const='clang',
    #                    default='gcc',
    #                    help='Use CLANG compiler (default is "gcc")')
    parser.add_argument('--bindir',dest='bindir',action='store',
                        default=default_src,
                        help='Directory where binary image exists (default is `pwd`)')
    parser.add_argument('--fndir',dest='fndir',action='store',
                        default=default_src,
                        help='Directory where Function Source exists (default is `pwd`)')

    parser.add_argument('--external-funcs',dest='externFns',nargs='+',
                        default=None,
                        help='format => patchFunction:<comma-separated list of external funcs> Modify function JUMP with Comma separated list of external functions whose addresses will be pushed onto the stack consistent with the call order as if the function was defined with void pointers of this same order [THIS MEANS THAT THIS ORDER MATTERS!]')


    parser.add_argument('--do-not-override-so', dest='so_override', action='store_const', const=False, default=True)
    #parser.add_argument('--just-seg', dest='just_seg', action='store_const', const=True, default=False)
    parser.add_argument('--debug', dest='debug', action='store_const', const=True, default=False)
    args = parser.parse_args()
    global debug
    #global just_seg
    debug = args.debug
    #just_seg = args.just_seg
    print(args.funcs)
    return args

def compile_so(compiler,patchfile,hook_filename,hook_cflags,enable_diet):
    import subprocess,shlex
    #hook_cflags="-fPIC -Wl,-T script.ld -nostdlib -nodefaultlibs -fkeep-inline-functions -fno-stack-protector -shared"
    #compile_command='{} -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared {} -o {}'.format(
    hcflags=hook_cflags
    hldflags=None
    compfile=hook_filename
    ldfile=None
    ld_command=None
    compile_command='{} {} {} -o {}'.format(
                    compiler,hcflags,patchfile,compfile)
    if 'COMPILE(' in hook_cflags:
        import re
        p=re.compile("^COMPILE\((.*)\):LINK\((.*)\)$")
        m=p.search(hook_cflags)
        if not m:
            print(hook_cflags)
            print("you have some regexp error")
        hcflags=m.group(1)
        hldflags=m.group(2)
        if hldflags != "":
            print("No linking options")
            compfile=patchfile[:-2]+".o"
            ldfile=hook_filename
            ld_command='{0} {4} -o {3} {2} {1}'.format(compiler,hldflags,compfile,ldfile,hcflags)
            compile_command='{} {} -c {} -o {}'.format(
                        compiler,hcflags,patchfile,compfile)
        else:
            compile_command='{} {} {} -o {}'.format(
                    compiler,hcflags,patchfile,compfile)

    if enable_diet:
        diet_path=os.environ.get("DIET64PATH")
        if '-m32' in hook_cflags:
            diet_path=os.environ.get("DIET32PATH")
        compile_command = "{0}/diet_{1}".format(diet_path,compile_command)
        if ld_command:
            ld_command = "{0}/diet_{1}".format(diet_path,ld_command)
            
        #compile_command = "diet {1}".format(diet_path,compile_command)
    dprint("Compilation command : \n\t%> "+compile_command)
    print("Compilation command : \n\t%> "+compile_command)
    if ld_command:
        dprint("Linking command : \n\t%> "+ld_command)
        print("Linking command : \n\t%> "+ld_command)

    cstatus=0
    lstatus=0
    try:
       proc= subprocess.Popen(shlex.split(compile_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
       cout,cerr = proc.communicate()
       ctatus = proc.returncode
       if cstatus:
          dprint("Compile error: \n{}\n{}".format(cout.decode('ascii'),cerr.decode('ascii')))
          print("Compile error: \n{}\n{}".format(cout.decode('ascii'),cerr.decode('ascii')))
    except subprocess.CalledProcessError as e:
       dprint("Compile command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(compile_command,
       "\n".join(cout.decode('ascii')),"\n".join(cerr.decode('ascii'))))
       print("Compile command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(compile_command,
       "\n".join(cout.decode('ascii')),"\n".join(cerr.decode('ascii'))))
       raise e
    dprint("Compile status: {}".format(cstatus))
    if ld_command:
        try:
           proc= subprocess.Popen(shlex.split(ld_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
           cout,cerr = proc.communicate()
           lstatus = proc.returncode
           if lstatus:
              dprint("Linking error: \n{}\n{}".format(cout.decode('ascii'),cerr.decode('ascii')))
              print("Linking error: \n{}\n{}".format(cout.decode('ascii'),cerr.decode('ascii')))
        except subprocess.CalledProcessError as e:
           dprint("Linking command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(ld_command,
           "\n".join(cout.decode('ascii')),"\n".join(cerr.decode('ascii'))))
           print("Linking command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(ld_command,
           "\n".join(cout.decode('ascii')),"\n".join(cerr.decode('ascii'))))
           raise e
        dprint("Linking status: {}".format(lstatus))
    return cstatus or lstatus

def generatePatchSO(compiler,patchfile,hook_cflags,enable_diet):
    """
    purpose: if --fn provided is a *.c file, compile it into a .so file
    """
    pfile = patchfile
    working_dir = os.path.realpath(".")
    status = -1
    #if os.path.exists(hook_filename):
    if not override_so:
        if os.path.isfile(hook_filename):
            print("SO file already exists [{}]".format(hook_filename))
            dprint("SO file already exists [{}]".format(hook_filename))
            status=0
        else:
            print("SO file does not already exist [{}]".format(hook_filename))
            dprint("SO file does not already exist [{}]".format(hook_filename))
            status = compile_so(compiler,pfile,hook_filename,hook_cflags,enable_diet)
    else:
        status = compile_so(compiler,pfile,hook_filename,hook_cflags,enable_diet)
    return status,"{0}/{1}".format(working_dir,hook_filename)

def hookFunctionIsStandalone(hook_binary):
    print("-W- WARNING: Standalone Binary Checking for new function is not implemented!")
    dprint("-W- WARNING: Standalone Binary Checking for new function is not implemented!")
    standalone=True
    problems= list()
    return standalone,problems

def inject_code(binary_to_update:lief.Binary,address:int,new_code:bytearray):
    # basic function that injects code w/o any data checking
    return binary_to_update.patch_address(address,new_code),len(new_code)

def change_function_content(binary_to_update:lief.Binary,
                            func_name:str,
                            my_code:bytearray):
    dprint("Changing function '{}'".format(func_name))
    their_funcsym = binary_to_update.get_symbol(func_name)
    their_fn = binary_to_update.section_from_virtual_address(their_funcsym.value)
    if their_funcsym.size < len(my_code):
        dprint("WARNING: Code being injected is larger than original code")
        dprint("original size: {}".format(their_funcsym.size))
        dprint("patch size: {}".format(len(my_code)))
        dprint("Overrun size: {}".format(len(my_code)-their_funcsym.size))
    return inject_code(binary_to_update,their_funcsym.value,my_code)

def generate_void_ptr_push(voidptr_address:int,cur_eip_offset:int=0,is32b:bool=True):
    # this is for 32b
    # from Fish: this will relatively call the function located at offset_to_the_function
    # call $+5                                     => E8 00 00 00 00
    # pop eax  <= this should be pop eax           => 58
    # add eax, offset_to_the_function (@ 03020100) => 05 00 01 02 03
    # call eax <= this should now be push eax      => 50
    # total # of bytes for this: 12

    # call $+5 => E8 00000000
    hex_string = bytearray.fromhex("e8")
    hex_addr = int(0).to_bytes(4,byteorder='little')
    hex_string.extend(hex_addr)
    current_offset=len(hex_string)
    # pop eax => 58
    hex_string.extend(bytes.fromhex("58"))
    # add eax => 05 <address>
    hex_string.extend(bytes.fromhex("05"))
    # instruction length is 5, so $eip is pointing at curr_offset
    rel_offset = voidptr_address-(cur_eip_offset+current_offset)
    hex_addr = (rel_offset.to_bytes(4,byteorder='little',signed=True))
    print("rel_offset = cur_eip_offset - voidptr_address")
    print("{0:10} = {2:13}  - {1:15}".format(rel_offset,cur_eip_offset+current_offset,voidptr_address))
    print("{0:10x} = {2:13x}  - {1:15x}".format(rel_offset,cur_eip_offset+current_offset,voidptr_address))
    print("hex val of rel_offset: {}".format(hex_addr.hex()))
    hex_string.extend(hex_addr)
    # push eax => 50
    hex_string.extend(bytes.fromhex("50"))
    #hex_string.extend(bytes.fromhex("33c0"))
    #hex_string.extend(bytes.fromhex("50"))
    print("push {} VOID* Instructions: {}".format(len(hex_string),hex_string))
    return hex_string

def generate_jump_from_dest_address(dest_address:int,offset:int=0):
    # this should really be changed to some python library 
    # that converts an assembly instruction to bytearray
    # there could be some endian-ness issues with "big" endian
    # the following is a relative jump near opcode, where relative offset is based on next instruction
    # hence the dest_addr-5 
    hex_string = bytearray.fromhex("e9")
    # relative address 0+%rip
    # %eip/%rip is pointing at next instruction, so offset+5
    hex_addr = (dest_address-(offset+5)).to_bytes(4,byteorder='little')
    hex_string.extend(hex_addr)
    dprint("JUMP Instruction: {}".format(hex_string))
    return hex_string

def change_function_to_jump(binary_to_update:lief.Binary,func_name:str,
                            dest_address:int,offset:int=0,
                            func_list:list=None,func_dict:dict=None
                           ):
    cur_offset=offset
    func_to_update = binary_to_update.get_symbol(func_name)
    print("SYMBOL: Function {} @ offset 0x{:x}".format(func_name,func_to_update.value))
    try:
        print("DYN SYMBOL: Function {} @ offset 0x{:x}".format(func_name,
          binary_to_update.get_dynamic_symbol(func_name).value
        ))
    except:
        pass
    hex_string=bytearray()
    rev_funclist=func_list
    # need to add the void* parameters in reverse order
    if rev_funclist:
       rev_funclist.reverse()
       print("Function list: {}".format(rev_funclist))
       # pop off return address from stack
       # pop ecx => 59
       hex_string+=bytearray.fromhex("59")
       cur_offset=len(hex_string)+offset
       # push ebx => 53
       hex_string+=bytearray.fromhex("53")
       cur_offset=len(hex_string)+offset
       for i in rev_funclist:
           address=func_dict[i]
           print("0x{:x} + 0x{:x} = 0x{:x}".format(func_to_update.value,cur_offset,
           func_to_update.value+cur_offset))
           hex_string+=generate_void_ptr_push(address,func_to_update.value+cur_offset)
           cur_offset=len(hex_string)+offset

       # push ecx => 51
       hex_string+=bytearray.fromhex("51")
       print("hex_string[{}] => {}".format(len(hex_string),hex_string));
    cur_offset=len(hex_string)+offset
    dprint("Original address: {:08x}".format(dest_address))
    hex_string += generate_jump_from_dest_address(dest_address,cur_offset)
    my_function_call = hex_string
    print("my_function_call[{}] => {}".format(len(my_function_call),my_function_call))
    return change_function_content(binary_to_update,func_name,my_function_call)

def replaceSymbol(binary:lief.Binary,orig_name:str,new_fn_name):
    # let's process the dynamic symbol first if it exists
    if binary.has_dynamic_symbol(orig_name):
        new_symbol=binary.get_dynamic_symbol(orig_name)
        new_symbol.name=new_fn_name
    orig_symbol = binary.get_symbol(orig_name)
    osymndx = int(orig_symbol.shndx)
    #if orig_symbol.symbol_version.value == 1:
    #    orig_symbol.name = new_fn_name
    #elif orig_symbol.symbol_version.value == 0:
    new_symbol = lief.ELF.Symbol()
    dprint("orig symbol   : {} [shndx = {}]".format(orig_symbol,orig_symbol.shndx))
    dprint("default symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    new_symbol.name = new_fn_name
    new_symbol.binding = orig_symbol.binding
    new_symbol.type = orig_symbol.type 
    new_symbol.value = orig_symbol.value 
    symbol_version = None
    if orig_symbol.has_version:
        try:
            new_symbol.symbol_version = lief.ELF.SymbolVersion(orig_symbol.symbol_version.value)
        except Exception as e:
            print("Exception when creating new symbol:"+str(e))
            pass
    new_symbol.size = orig_symbol.size
    new_symbol.shndx = osymndx
    new_symbol.other = orig_symbol.other
    new_symbol.imported = orig_symbol.imported
    new_symbol.exported = orig_symbol.exported
    dprint("updated symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    binary.remove_static_symbol(orig_symbol)
    dprint("removed original symbol: {}".format(orig_name))
    dprint("modified symbol: {}".format(new_symbol))
    new_symbol=binary.add_static_symbol(new_symbol)
    new_symbol.shndx = osymndx
    dprint("added/modified symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    if new_symbol.shndx != osymndx:
        dprint("Original symbol's index is: {}".format(orig_symbol.shndx))
        dprint("New symbol      => {}".format(new_symbol.shndx))
        raise ValueError
    return new_symbol

def change_func_name(orig_name:str,new_name:str,binary:lief.Binary):
    renamed_symbol=replaceSymbol(binary,orig_name,new_name)
    return renamed_symbol

def patch_pltgot_with_added_segment(binary_to_update:lief.Binary,patch_binary:lief.Binary,
    patch_fn_name:str, segment:lief.ELF.Segment=None):
    """
    this function is lifted from LIEF example 05
     What it does is:
       1) Adds a new segment into the binary image to update 
            -> NOTE: New segment is the first segment of the patch binary
               this COULD be an issue with larger binary patches
       2) finds the symbol of the function we want to patch in original binary
       3) calculates the new address of the inserted code (new segment's VA + function offset)
       4) patches the PLT/GOT for the original function with new address (new segment + function offset)
       THIS ONLY WORKS WITH ORIGINAL FUNCTIONS THAT ARE IMPORTED
    """
    their_fn = binary_to_update.get_symbol(patch_fn_name)
    success = None
    if their_fn.imported and their_fn.is_function:
        if not segment:
            dprint("Adding Segment: {}".format(patch_binary.segments[0]))
            segment = binary_to_update.add(patch_binary.segments[0])
        else:
            dprint("Segment already exists: {}".format(segment))
        my_fn = patch_binary.get_symbol(patch_fn_name)
        my_fn_addr = segment.virtual_address + my_fn.value
        binary_to_update.patch_pltgot(patch_fn_name,my_fn_addr)
        success = True
    else:
        if not their_fn.is_function:
            print("WARNING: function {patch_fn_name} isn't a function in binary to patch.")
        if not their_fn.imported:
            print("WARNING: function {patch_fn_name} isn't imported in binary to patch.")
        print("WARNING: Can't apply patch_pltgot method")
        success = False
    return success,binary_to_update,segment

def patch_func_with_jump_to_added_segment(binary_to_update:lief.Binary,patch_binary:lief.Binary,
    patch_fn_name:str, segment:lief.ELF.Segment=None, ext_funcs:list=None):
    """
    this function is similar to LIEF example 05
     What it does is:
       1) Adds a new segment into the binary image to update 
            -> NOTE: New segment is the first segment of the patch binary
               this COULD be an issue with larger binary patches
       2) finds the symbol of the function we want to patch in original binary
       3) calculates the new address of the inserted code (new segment's VA + function offset)
       4) patches the original function with a JUMP to new address (new segment + function offset)
       THIS ONLY WORKS WITH ORIGINAL FUNCTIONS THAT ARE LOCAL
    """
    their_fn = binary_to_update.get_symbol(patch_fn_name)
    success = None
    extfncs = None if not ext_funcs else dict()
    
    little_endian = True if binary_to_update.abstract.header.endianness == lief.ENDIANNESS.LITTLE else False
    if not their_fn.imported and their_fn.is_function:
        if not segment:
            #binary_to_update.write("orig_bin.bin")
            dprint("Adding Segment:\n[----- \n {}\n] -----".format(patch_binary.segments[0]))
            patch_segments = patch_binary.segments[0]
            orig_rodata_VA=binary_to_update.concrete.get_section(".rodata").virtual_address
            segment = binary_to_update.add(patch_segments)
            binary_to_update.write("added_seg.bin")
            sym=None
            fixme=False
            if binary_to_update.name == "AIS-Lite":
                sym=binary_to_update.get_symbol("EPFD")
                fixme=True
            if binary_to_update.name == "ASCII_Content_Server":
                sym=binary_to_update.get_symbol("InitialInfo")
                fixme=True
            if fixme:
                esize= 8 if binary_to_update.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else 4
                section=binary_to_update.sections[sym.shndx]
                dprint(hex(section.virtual_address))
                dprint(hex(sym.value))
                sym_offset=(sym.value-section.virtual_address)+sym.size-esize
                dprint(hex(sym_offset))
                dprint(sym_offset)
                content = section.content[sym_offset:sym_offset+esize]
                ptr_val = int.from_bytes(content, byteorder="little" if little_endian else "big")
                rodata_VA=binary_to_update.concrete.get_section(".rodata").virtual_address
                offset=rodata_VA-orig_rodata_VA
                new_ptr_val=ptr_val+offset
                new_code = new_ptr_val.to_bytes(4,byteorder='little' if little_endian else 'big')
                address = section.virtual_address + sym_offset
                binary_to_update.patch_address(address,new_ptr_val,4)
                print("{} workaround - offset: {} , orig content: {}, expected content: {} or 0x{:x}".format(binary_to_update.name,address,content,new_code,new_ptr_val))
                print("=> actual content: {}".format(section.content[sym_offset:sym_offset+4]))

                
                
        else:
            dprint("Segment already exists: {}".format(segment))
        
        their_fn = binary_to_update.get_symbol(patch_fn_name)
        if ext_funcs:
            mydecl=""
            for i in ext_funcs:
                mydecl+="void* {},".format(i)
                try:
                   j=binary_to_update.get_symbol(i)
                   address=None
                   if j.imported:
                       try:
                           xrelo=binary_to_update.get_relocation(i)
                           address=xrelo.address
                       except:
                           print("ERROR! symbol '{}' cannot be resolved!".format(i))
                           import sys;sys.exit(1)
                   else:
                      address=j.value
                   extfncs[i]=address
                   dprint("External function: {} @ {}".format(i,hex(extfncs[i])))
                except Exception as e:
                   print("Exception occurred when trying to find external function symbol {}".format(i))
                   print("ERROR: {}".format(e))
                   import sys; sys.exit(1)
            print("| NOTE: expecting function declaration like so:\n")
            print("| \t {}({}...)\n".format(patch_fn_name,mydecl))
        #import sys;sys.exit(1)
        dprint("Using Segment:\n[---- \n {}\n] -----\n@ 0x{:08x}".format(segment,segment.virtual_address))
        dprint("Segment type is :{}".format(segment.type))
        my_fnsym = patch_binary.get_symbol(patch_fn_name)
        dprint("Their function symbol [is_function = {}] [is_static = {}] :\n {} @ 0x{:04x}".format(
                their_fn.is_function, their_fn.is_static,
                their_fn,their_fn.value 
                ))
        fn_segment = binary_to_update.segment_from_virtual_address(their_fn.value)
        dprint("Their function segment: @ {:04x}".format(fn_segment.virtual_address))
        dprint("my function segment @ {:04x} + offset {:04x}".format(segment.virtual_address,my_fnsym.value))
        renamed_fn = patch_fn_name
        renamed_fnsym = binary_to_update.get_symbol(renamed_fn)
        if RENAME_FUNCTION:
            renamed_fn = "m"+patch_fn_name
            renamed_fnsym = change_func_name(patch_fn_name,renamed_fn,binary_to_update)
        my_fn_addr = None
        segment_VA=segment.virtual_address
        if patch_binary.header.file_type == lief.ELF.E_TYPE.DYNAMIC:
            dprint("DYNAMIC PATCH BINARY")
            my_fn_addr = segment.virtual_address + my_fnsym.value
            dprint("Relative offset from their function to patch function : {:04x}".format(my_fn_addr-their_fn.value))
            dprint("{:08x} => relative jump address [func.value] {:08x}".format(my_fn_addr,my_fn_addr-their_fn.value))
            dprint("{:08x} => relative jump address [func.value] {:08x} [their function value: {:08x}]".format(my_fn_addr,my_fn_addr-their_fn.value,their_fn.value))
            dprint("segment virtual address {:08x} ".format(segment_VA))
            dprint("virtual address {:08x} ".format(my_fn_addr))
            dprint("my_fnsym.value {:08x} ".format(my_fnsym.value))
            dprint("segment offset {:x} [ virtual address {:08x} ]".format(
                          binary_to_update.virtual_address_to_offset(segment_VA),
                          segment_VA))
            dprint("segment content @ {:x} : {}".format(
                          binary_to_update.virtual_address_to_offset(segment_VA),
                          bytearray(binary_to_update.get_content_from_virtual_address(segment_VA,28)).hex()))
            dprint("offset {:x} [ virtual address {:08x} ]".format(
                          binary_to_update.virtual_address_to_offset(my_fn_addr),
                          my_fn_addr))
        else:
            dprint("STATIC PATCH BINARY")
            dprint("new segment's file_offset => {:08x}".format(segment.file_offset))
            dprint("new segment's virtual address => {:08x}".format(segment.virtual_address))
            #TODO
            dprint("patch binary's function's segment's virtual address => {:08x}".format(patch_binary.sections[my_fnsym.shndx].segments[0].virtual_address))
            dprint("patch binary's function's address => {:08x}".format(my_fnsym.value))

            patch_segment_virtual_address = patch_binary.sections[my_fnsym.shndx].segments[0].virtual_address
            # need to update the .got.plt entries from injected section by adding this value (probably negative)
            segment_offset_delta = segment.virtual_address - patch_segment_virtual_address
            # the following is the new jump address => my_fnsym.value = patch_segment_virtual_address + function_offset
            # so =>  my_fnsym.value-patch_segment_virtual_address = function_offset
            # therefore, my_fn_addr = segment.virtual_address + function_offset
            dprint("Segment offset delta : {}".format(segment_offset_delta))
            #import sys; sys.exit(-1);
            my_fn_addr = segment.virtual_address + \
                         (my_fnsym.value-patch_segment_virtual_address)
            dprint("Relative offset from their function to patch function : {:04x}".format(my_fn_addr-their_fn.value))
            change_function_to_jump(binary_to_update,func_name=renamed_fn,
                                    dest_address=(my_fn_addr-their_fn.value),
                                    func_list=ext_funcs,func_dict=extfncs
                                    )
            dprint("{:08x} => relative jump address [func.value] {:08x}".format(my_fn_addr,my_fn_addr-their_fn.value))
            dprint("{:08x} => relative jump address [func.value] {:08x} [their function value: {:08x}]".format(my_fn_addr,my_fn_addr-their_fn.value,their_fn.value))
            dprint("virtual address {:08x} ".format(my_fn_addr))
            dprint("Patch Binary's ELF class => {}".format(patch_binary.header.identity_class))
            default_entry_size= 8 if patch_binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64 else 4
            little_endian = True if patch_binary.abstract.header.endianness == lief.ENDIANNESS.LITTLE else False
            plt_section_offset=patch_binary.concrete.get_section(".plt").offset
            got_section_offset=patch_binary.concrete.get_section(".got").offset
            # now let's update the old contents of the .got.plt and .got sections of the 
            #  patch_binary to reflect the new segment offset
            #myPLT = dict()
            #for x in [ ".got.plt",".got" ]:
            #    section = patch_binary.concrete.get_section(x)
            #    contents = section.content
            #    offset = section.offset
            #    file_offset = section.file_offset
            #    entry_size = section.entry_size if section.entry_size != 0 else default_entry_size
            #    size = section.size
            #    num_entries = int(size/entry_size)
            #    content_offset = section.virtual_address-patch_segment_virtual_address
            #    dprint("{} size '{}' ".format(x,size))
            #    dprint("{} entry_size '{}' ".format(x,entry_size))
            #    dprint("{} file_offset '{:08x}' ".format(x,file_offset))
            #    dprint("{} offset '{:08x}' ".format(x,offset))
            #    dprint("{} number of entries '{}' ".format(x,num_entries))
            #    dprint("{} content:\n'{}'\n[ @ VA {:08x} => {:08x}]".format(
            #                  x,
            #                  bytearray(contents).hex(),
            ##                  section.virtual_address,
            #                  content_offset
            #                  ))
            #    dprint("segment content @ content_offset = 0x{:08x} :\n'{}'".format( content_offset,
            #                  bytearray(segment.content[content_offset:content_offset+size]).hex()
            #          ))
            #    dprint("Segment file_offset = 0x{:016x}".format(content_offset))
            #    #import sys; sys.exit(-1);
            #    for i in range(num_entries):
            #        # this is the .got or .got.plt entry whose content is an absolute address for that function
            #        dest_addr_offset = content_offset+(i*entry_size)
            #        absolute_dest_addr_offset = section.virtual_address + (i*entry_size)
            #        myPLT[absolute_dest_addr_offset] = dict()
            #        entry_value = contents[i*entry_size:(i+1)*entry_size]
            #        dprint("{} entry #{} => '{}' ".format(x,i,entry_value))
            #        addr_entry_value = int.from_bytes(bytes(entry_value),byteorder='little' if little_endian else 'big')
            #        dprint("{} addr_entry_value of entry #{} => '0x{:016x}' ".format(x,i,addr_entry_value))
            #        # the original table entry value
            #        myPLT[absolute_dest_addr_offset]["orig"]=addr_entry_value
            #        # need to calculate the segment_offset
            #        myPLT[absolute_dest_addr_offset]["segment_offset"]=None
            #        # updated address => address_value = addr_entry_value+segment_offset_delta
            #        if addr_entry_value > patch_segment_virtual_address:
            #            new_addr_value = addr_entry_value+segment_offset_delta
            #            myPLT[absolute_dest_addr_offset]["segment_offset"]=addr_entry_value-patch_segment_virtual_address
            #        else:
            #            new_addr_value = addr_entry_value
            #        entry_segment_offset = new_addr_value.to_bytes(entry_size,byteorder='little' if little_endian else 'big')
            #        #this doesn't seem to work the way I expected, instead let's edit the segment's content
            #        #dest_addr_offset = segment.virtual_address + offset+(i*entry_size)
            #        #TODO inject_code(binary_to_update:lief.Binary,address:int,new_code:bytearray):
            #        #dest_addr_offset = content_offset+(i*entry_size)
            #        #segment.content[dest_addr_offset:dest_addr_offset+entry_size] = entry_segment_offset

            #        dprint("Changing {} to {} ".format(segment.content[dest_addr_offset:dest_addr_offset+entry_size],entry_segment_offset))
            #        inject_code(binary_to_update,segment.virtual_address+dest_addr_offset,bytearray(entry_segment_offset))
            #        dprint("Updated contents => {} ".format(segment.content[dest_addr_offset:dest_addr_offset+entry_size]))
            #        dprint("{} new_addr_value of entry #{} => '0x{:016x}' @ address {:08x} ".format(x,i,new_addr_value,dest_addr_offset))
            #    dprint("{} @ 0x{:016x} => segment.virtual_address : '0x{:016x}' + offset :'0x{:016x}' ".format(
            #    x,segment.virtual_address+content_offset,segment.virtual_address,content_offset))
            #    #import sys; sys.exit(-1);
            ##dprint("Segment offset delta : {}".format(segment_offset_delta))
            #section = patch_binary.concrete.get_section(".plt")
            #contents = section.content
            #offset = section.offset
            #file_offset = section.file_offset
            #entry_size = section.entry_size if section.entry_size != 0 else default_entry_size
            #size = section.size
            #num_entries = int(size/entry_size)
            #content_offset = section.virtual_address-patch_segment_virtual_address

            #----- start of processing the .rela.plt
            # sooooooooo how's this going to work:
            # For each i in .rela.plt:
            #     1) my_gotplt_address = i.address
            #     2) my_func_address = i.addend
            #     3) translt_gotplt_offset=my_gotplt_address-patch_segment_virtual_address
            #     4) translt_func_address=my_func_address-patch_segment_virtual_address + segment.virtual_address
            #     5) segment.content[translt_gotplt_offset:+entry_size]= translt_func_address 
            #               => translt_func_address.to_bytes(entry_size,byteorder='little' if little_endian else 'big')
            myPLT = list()
            for i,rel in enumerate(patch_binary.relocations):
                if not rel.is_rela:
                    dprint("Relocation entry #{}'s [ address: {}; added: {} ] is_rela is False => this scheme not supported".format(
                    rel,rel.address,rel.addend))
                else:
                    my_gotplt_address = rel.address
                    my_func_address = rel.addend
                    trnsltd_gotplt_offset = my_gotplt_address - patch_segment_virtual_address
                    trnsltd_func_offset = my_func_address - patch_segment_virtual_address
                    trnsltd_func_address = trnsltd_func_offset + segment.virtual_address
                    dprint("____________________________")
                    dprint("| rel.addr : {:08x} | rel.addend : {:08x} | trns.addr : {:08x} | trns.addend : {:08x} |".format(
                         rel.address,rel.addend,trnsltd_gotplt_offset,trnsltd_func_address
                         )
                         )
                    dprint("| {} | {} | {} | {} |".format(
                         type(rel.address),
                         type(rel.addend),
                         type(trnsltd_gotplt_offset),
                         type(trnsltd_func_address)
                         )
                         )
                    dprint("| {} | {} | {} | {} |".format(
                              list((rel.address).to_bytes(default_entry_size,byteorder="little" if little_endian else "big")),
                              list((rel.addend).to_bytes(default_entry_size,byteorder="little" if little_endian else "big")),
                              list((trnsltd_gotplt_offset).to_bytes(default_entry_size,byteorder="little" if little_endian else "big")),
                              list((trnsltd_func_address).to_bytes(default_entry_size,byteorder="little" if little_endian else "big"))
                              )
                         )
                    orig_pltvalue = segment.content[trnsltd_gotplt_offset:trnsltd_gotplt_offset+default_entry_size]
                    orig_pltvalue_int = int.from_bytes(orig_pltvalue, byteorder="little" if little_endian else "big")
                    # actual .got value is 6 bytes ahead of the .plt entry (points to "66 90" that immediate follows JUMP)
                    plt_offset = orig_pltvalue_int - patch_segment_virtual_address - 6
                    dprint("Original .got.plt value @ {:08x} => {} ( original plt value : {:08x} ) [ PLT OFFSET : {:08x} ]".format(
                            trnsltd_gotplt_offset,
                            list(orig_pltvalue),
                            orig_pltvalue_int,
                            plt_offset
                            )
                        )
                    dprint("Expected .got.plt update value => {}".format(list(
                        trnsltd_func_address.to_bytes(default_entry_size,byteorder="little" if little_endian else "big")))
                        )
                    rel_plt_entry = {
                            'orig_got_entry':orig_pltvalue_int,
                            'plt_segment_offset': plt_offset,
                             'orig':
                                  {'address':rel.address,'addend':rel.addend},
                             'relative_to_segment':
                                  {'address':trnsltd_gotplt_offset,'addend':trnsltd_func_offset}
                           }
                    myPLT.append(rel_plt_entry)
                    jump_relative_offset = trnsltd_func_offset-plt_offset
                    dprint("| creating relative jump    ====   |")
                    dprint("| {:08x} = {:08x} - {:08x} |".format(
                          jump_relative_offset,
                          trnsltd_func_offset,
                          plt_offset
                          )
                         )
                    jump_instruction = generate_jump_from_dest_address(jump_relative_offset)
                    plt_address = segment.virtual_address+plt_offset
                    orig_segment_contents = segment.content[plt_offset:plt_offset+8]
                    dprint("Original .plt entry => {}".format(bytes(orig_segment_contents).hex()))
                    inject_code(binary_to_update=binary_to_update,address=plt_address,new_code=jump_instruction)
                    #segment.content[trnsltd_gotplt_offset:trnsltd_gotplt_offset+default_entry_size] = \
                    #    trnsltd_func_address.to_bytes(default_entry_size,byteorder="little" if little_endian else "big")
                    changed_segment_contents = segment.content[plt_offset:plt_offset+8]
                    dprint("Updated .plt entry => {}".format(bytes(changed_segment_contents).hex()))
                # TODO ++++++ NOTE FROM PEMMA ++++++++ I THINK I STILL NEED TO CHANGE THE .plt to JUMP to the offset
                ### but the above code can be used to generate a my_plotgot table
                
        if my_fn_addr is None: 
            print("Patch input file is not DYNAMIC, RELOCATABLE, or EXECUTABLE")
            print("Cannot support this patch type")
            sys.exit(-1);
        change_function_to_jump(binary_to_update,func_name=renamed_fn,
                                dest_address=(my_fn_addr-their_fn.value),
                                func_list=ext_funcs,func_dict=extfncs)
        dprint("content '{}' @ {:08x} ]".format(
                              bytearray(binary_to_update.get_content_from_virtual_address(segment.virtual_address,28)).hex(),
                              segment.virtual_address))
        dprint("content '{}' @ {:08x} ]".format(
                              bytearray(binary_to_update.get_content_from_virtual_address(my_fn_addr,28)).hex(),
                              my_fn_addr))
        success = True
    else:
        if not their_fn.is_function:
            print("WARNING: function {patch_fn_name} isn't a function in binary to patch.")
        if their_fn.imported:
            print("WARNING: function {patch_fn_name} is imported in binary to patch.")
        print("WARNING: Can't apply patch_pltgot method")
        success = False
    
    # Remove bind now if present
    if lief.ELF.DYNAMIC_TAGS.FLAGS in binary_to_update:
        dprint("lief.ELF.DYNAMIC_TAGS.FLAGS")
        flags = binary_to_update[lief.ELF.DYNAMIC_TAGS.FLAGS]
        flags.remove(lief.ELF.DYNAMIC_FLAGS.BIND_NOW)
    
    if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in binary_to_update:
        dprint("lief.ELF.DYNAMIC_TAGS.FLAGS_1")
        flags = binary_to_update[lief.ELF.DYNAMIC_TAGS.FLAGS_1]
        flags.remove(lief.ELF.DYNAMIC_FLAGS_1.NOW)
    
    # Remove RELRO
    if lief.ELF.SEGMENT_TYPES.GNU_RELRO in binary_to_update:
        dprint("lief.ELF.SEGMENT_TYPES.GNU_RELRO")
        binary_to_update[lief.ELF.SEGMENT_TYPES.GNU_RELRO].type = lief.ELF.SEGMENT_TYPES.NULL
    
    return success,binary_to_update,segment

def inject_hook(inputbin:str,outputbin:str,hook_file:str,
                override_functions:list,extFns:dict):
    # currently developed with assumption that functions being patched exist in input binary image
    # and not an external dynamic shared object/library
    #imported_libs = modifyme.imports
    #lief.Logger.enable()
    #lief.Logger.set_level(lief.LOGGING_LEVEL.DEBUG)
    modifyme = lief.ELF.parse(inputbin)
    hookme = lief.ELF.parse(hook_file)
    if not modifyme:
        print("lief.parse({}) failed for some reason".format(inputbin))
    if not hookme:
        print("lief.parse({}) failed for some reason".format(hook_file))
        raise
    success = True
    segment = None
    dynlib  = None
    for fn in override_functions:
        external_funcs = None if ((not extFns) or (fn not in extFns)) else extFns[fn]
        my_fn=None
        their_fn=None
        try:
            my_funcsym = hookme.get_symbol(fn)
        except Exception as e:
            print("ERROR: Couldn't find function '{}' in '{}'".format(fn,hook_filename))
            print("looked for '{}' in '{}'".format(my_funcsym.name,hook_filename))
            print("Tried to find '{}' in '{}'".format(my_funcsym.value,hook_filename))
            print(e)
            success = False
            raise e
        try:
            their_funcsym = modifyme.get_symbol(fn)
        except Exception as e:
            print("ERROR: Couldn't find function '{}' in '{}'".format(fn,inputbin))
            print("looked for '{}' in '{}'".format(their_funcsym.name,inputbin))
            print("Tried to find '{}' in '{}'".format(their_funcsym.value,inputbin))
            print(e)
            success = False
            raise e
        if success:
            standalone,problems= hookFunctionIsStandalone(hookme)
            if not standalone:
                print("ERROR: {} loads external libraries".format(hook_file))
                print("Please address the following:\n{}".format(problems))
                print("\nExiting.\n")
                import sys
                sys.exit(-1);
            success = False
            modified = None
            my_fn = hookme.section_from_virtual_address(my_funcsym.value)
            their_fn = modifyme.section_from_virtual_address(their_funcsym.value)
            if their_funcsym.imported and their_funcsym.is_function:
               dprint("patching pltgot [function in added segment]")
               success,modifyme,segment = patch_pltgot_with_added_segment(modifyme,
                                                hookme,
                                                fn,
                                                segment)
            elif their_funcsym.is_function and not their_funcsym.imported:
               dprint("injecting jump to [function in added segment]")
               success,modifyme,segment = patch_func_with_jump_to_added_segment(modifyme,
                                                hookme,
                                                fn,
                                                segment,
                                                external_funcs)
            else:
               print("ERROR: {} is not a function in {}".format(fn,inputbin))
               print("\nExiting.\n")
               import sys
               sys.exit(-1);
    print("Creating output : '{}'".format(outputbin))
    modifyme.write(outputbin)    
    return not success

def main(args):
    global override_so
    global hook_filename
    fn_list = args.funcs  
    input_fname = args.infile
    fn_fname = args.patchfile
    output_fname = args.outfile
    compiler = args.compiler
    bin_src_dir = args.bindir
    fn_src_dir = args.fndir
    override_so = args.so_override
    hook_cflags = args.cflags
    enable_diet = args.dietlibc
    genprog = args.genprog
    if not args.nodate or genprog:
        hook_filename = "libhook."+dateinfo+".so"
    pfile=fn_fname
    external_funcs = None
    if args.externFns:
        external_funcs=dict()
        import re
        p=re.compile("^(\w+):(.*)$")
        for i in args.externFns:
            m=p.search(i)
            fn=m.group(1)
            ptrs=m.group(2).split(',')
            external_funcs[fn]=ptrs
            dprint("{} => {}".format(fn,ptrs))
    if not os.path.exists(os.path.realpath("{}".format(fn_fname))):
        if not os.path.isfile(os.path.realpath("{}/{}".format(fn_src_dir,fn_fname))):
            import subprocess,shlex
            print("ERROR: '{}' file does not exist ".format(fn_fname,fn_src_dir))
            dprint("working directory contents:\n[\n{}\n]".format(subprocess.check_output(shlex.split("ls {}".format(fn_src_dir)))))
            dprint("ERROR: '{}' file does not exist ".format(fn_fname,fn_src_dir))
            return -1
        else:
            pfile="{}/{}".format(working_dir,fn_fname)
    
    orig_dir = os.path.realpath(".")
    os.chdir(fn_src_dir)
    status,fn_fullpath = generatePatchSO(compiler,pfile,hook_cflags,enable_diet)
    os.chdir(orig_dir)
    if not status:
       print("Successfully compiled '{}'".format(fn_fullpath))
    else:
       print("Could not compile '{}'".format(fn_fullpath))
       cleanup(bin_src_dir,hook_filename,input_fname,bin_fullpath,hook_cflags)
       import sys
       sys.exit(-1)
   
    bin_fullpath = os.path.realpath("{}/{}".format(bin_src_dir,input_fname))
    out_fullpath = os.path.realpath(output_fname)
    if not os.path.dirname(output_fname):
       out_fullpath = os.path.realpath("{}/{}".format(default_src,output_fname))
    #if not os.path.exists(os.path.realpath(bin_fullpath)):
    if not os.path.isfile(bin_fullpath):
       import subprocess,shlex
       print("ERROR: '{}' file does not exist in {}".format(bin_fullpath))
       dprint("binary source directory contents:\n[\n{}\n]".format(subprocess.check_output("ls {}".format(bin_src_dir))))
       dprint("ERROR: '{}' file does not exist in {}".format(bin_fullpath))
       return -1
    status = inject_hook(bin_fullpath,out_fullpath,fn_fullpath,fn_list,external_funcs)
    if not status:
       print("Successfully stitched ALL '{}' into '{}' as output '{}'".format(fn_list,input_fname,output_fname))
       dprint("Hook lib is generated in '{}'".format(hook_filename))
    chmod_mask = os.stat(bin_fullpath).st_mode & 0o777
    os.chmod(out_fullpath,chmod_mask)
    if genprog:
       if not status or not debug:
           os.remove(hook_filename)
       else:
           cleanup(bin_src_dir,hook_filename,input_fname,bin_fullpath,hook_cflags)


def cleanup(bin_src_dir,hook_filename,input_fname,bin_fullpath,hook_cflags):
   odebugdir=bin_src_dir+"/genprog_debug/"+dateinfo
   debug_dir=odebugdir
   i=0
   while os.path.isdir(debug_dir):
       debug_dir="{}.{}".format(odebugdir,i)
       i=i+1
   os.mkdir(debug_dir)
   os.rename(hook_filename,debug_dir+"/"+os.basename(hook_filename))
   os.rename(input_fname,debug_dir+"/"+os.basename(input_fname))
   os.copy(bin_fullpath,debug_dir+"/"+os.basename(input_fname))
   with open(debug_dir+"/compile_flags","w") as f:
       f.write(hook_cflags)
       
   dprint("Failure can be debugged at :\n{}".format(debugdir))



if __name__ == '__main__':
    arguments = parse_arguments()
    main(arguments)
