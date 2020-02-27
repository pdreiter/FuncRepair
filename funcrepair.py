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
default_cwd=os.path.realpath(".")
default_src=default_cwd

hook_filename = "libhook.so"


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
    parser.add_argument('--clang',dest='compiler', action='store_const', const='clang',
                        default='gcc',
                        help='Use CLANG compiler (default is "gcc")')
    parser.add_argument('--bindir',dest='bindir',action='store',
                        default=default_src,
                        help='Directory where binary image exists (default is `pwd`)')
    parser.add_argument('--fndir',dest='fndir',action='store',
                        default=default_src,
                        help='Directory where Function Source exists (default is `pwd`)')
    args = parser.parse_args()
    print(args.funcs)
    return args

def compile_so(compiler,patchfile,hook_filename):
    import subprocess,shlex
    compile_command='{} -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared {} -o {}'.format(
                    compiler,patchfile,hook_filename)
    try:
       proc= subprocess.Popen(shlex.split(compile_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
       cout,cerr = proc.communicate()
       status = proc.returncode
    except subprocess.CalledProcessError as e:
       print("Compile command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(compile_command,
       "\n".join(cout),"\n".join(cerr)))
       raise e
    return status

def generatePatchSO(compiler,patchfile,working_dir):
    """
    purpose: if --fn provided is a *.c file, compile it into a .so file
    """
    if not os.path.exists("{}/{}".format(working_dir,patchfile)):
       print("ERROR: '{}' file does not exist in {}".format(patchfile,working_dir))
       return -1
    
    orig_dir = os.path.dirname(os.path.realpath("."))
    os.chdir(working_dir)
    
    status = -1
    if os.path.exists(hook_filename):
        print("SO file already exists [{}]".format(hook_filename))
        status=0
    else:
        print("SO file does not already exist [{}]".format(hook_filename))
        status = compile_so(compiler,patchfile,hook_filename)
    os.chdir(orig_dir)
    return status,"{0}/{1}".format(working_dir,hook_filename)

def inject_code(binary_to_update:lief.Binary,address:int,new_code:bytearray):
    # basic function that injects code w/o any data checking
    return binary_to_update.patch_address(address,new_code),len(new_code)

def change_function_content(binary_to_update:lief.Binary,
                            func_name:str,
                            my_code:bytearray):
    print("Changing function '{}'".format(func_name))
    their_funcsym = binary_to_update.get_symbol(func_name)
    their_fn = binary_to_update.section_from_virtual_address(their_funcsym.value)
    if their_funcsym.size < len(my_code):
        print("WARNING: Code being injected is larger than original code")
        print("original size: {}".format(their_funcsym.size))
        print("patch size: {}".format(len(my_code)))
        print("Overrun size: {}".format(len(my_code)-their_funcsym.size))
    return inject_code(binary_to_update,their_funcsym.value,my_code)

def change_function_to_jump(binary_to_update:lief.Binary,func_name:str,dest_address:int):
    #my_function_call = "jmp 0x{}".format(hex(dest_address))
    # this should really be changed to some python library 
    # that converts an assembly instruction to bytearray
    print("Original address: {:08x}".format(dest_address))
    #hex_string = bytearray.fromhex("ff25")
    #hex_addr = int(0).to_bytes(4,byteorder='little')
    #hex_string.extend(hex_addr)
    hex_string = bytearray.fromhex("e9")
    # relative address 0+%rip
    hex_addr = (dest_address-5).to_bytes(4,byteorder='little')
    hex_string.extend(hex_addr)
    print("JUMP Instruction: {}".format(hex_string))
    my_function_call = hex_string
    #my_function_call.append(dest_address.to_bytes(4,byteorder='big'))
    # this is a placeholder until i get the whole call values 
    return change_function_content(binary_to_update,func_name,my_function_call)

def replaceSymbol(binary:lief.Binary,orig_name:str,new_fn_name):
    orig_symbol = binary.get_symbol(orig_name)
    osymndx = int(orig_symbol.shndx)
    new_symbol = lief.ELF.Symbol()
    print("orig symbol   : {} [shndx = {}]".format(orig_symbol,orig_symbol.shndx))
    print("default symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    new_symbol.name = new_fn_name
    new_symbol.binding = orig_symbol.binding
    new_symbol.type = orig_symbol.type 
    new_symbol.value = orig_symbol.value 
    symbol_version = None
    if orig_symbol.has_version:
        new_symbol.symbol_version = orig_symbol.symbol_version
        #symbol_version = orig_symbol.symbol_version
    new_symbol.size = orig_symbol.size
    new_symbol.shndx = osymndx
    new_symbol.other = orig_symbol.other
    new_symbol.imported = orig_symbol.imported
    new_symbol.exported = orig_symbol.exported
    #new_symbol = lief.ELF.Symbol(name=new_fn_name,
    #                             type=orig_symbol.type,
    #                             binding=orig_symbol.binding,
    #                             other=orig_symbol.other,
    #                             shndx=orig_symbol.shndx(),
    #                             value=orig_symbol.value,
    #                             size=orig_symbol.size)
    print("updated symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    binary.remove_static_symbol(orig_symbol)
    print("removed original symbol: {}".format(orig_name))
    #new_symbol.name = new_fn_name
    print("modified symbol: {}".format(new_symbol))
    new_symbol=binary.add_static_symbol(new_symbol)
    new_symbol.shndx = osymndx
    print("added/modified symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    if new_symbol.shndx != osymndx:
        print("Original symbol's index is: {}".format(orig_symbol.shndx))
        print("New symbol      => {}".format(new_symbol.shndx))
        raise ValueError

    return new_symbol
    
def change_func_name(orig_name:str,new_name:str,binary:lief.Binary):
    renamed_symbol=replaceSymbol(binary,orig_name,new_name)
    return renamed_symbol

def add_symbols(binary_to_update:lief.Binary,hook_symbol:lief.ELF.Symbol):
    print("add_symbols")
    orig_name = hook_symbol.name
    new_fn_name = "m"+orig_name
    # replace previous symbol with function name orig_name with 
    # renamed_symbol with new_fn_name as the name
    renamed_symbol=replaceSymbol(binary_to_update,orig_name,new_fn_name)
    # add a local symbol version
    symbol_version= lief.ELF.SymbolVersion(0)
    new_symbol = lief.ELF.Symbol() #copy.deepcopy(hook_symbol)
    new_symbol.name=orig_name
    # change original hook symbol name to something else 
    # can't set this
    #new_symbol.symbol_version = symbol_version
    new_symbol.imported = True
    new_symbol.size = 0
    new_symbol.value = 0
    new_symbol.type = lief.ELF.SYMBOL_TYPES.FUNC
    new_symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
    new_dyn_shndx = len(binary_to_update.dynamic_symbols)
    statsymbol= binary_to_update.add_static_symbol(new_symbol)
    dynsymbol= binary_to_update.add_dynamic_symbol(new_symbol,symbol_version)
    return new_fn_name,new_dyn_shndx,dynsymbol,statsymbol

def add_reladyn(binary_to_update:lief.Binary,sym:lief.ELF.Symbol,shndx:int):
    print("add_reladyn")
    # __init__(self: lief.ELF.Relocation,
    #          address: int, 
    #          type: int = 0, 
    #          addend: int = 0, 
    #          is_rela: bool = False) -> None
    next_addr = 0
    for x in binary_to_update.pltgot_relocations:
        if x.address > next_addr:
            next_addr = x.address + x.size
           
    relodyn = lief.ELF.Relocation(next_addr,
                                  type=lief.ELF.RELOCATION_X86_64.JUMP_SLOT,
                                  addend=0,
                                  is_rela=True
                                  )
    relodyn.symbol = sym
    #relodyn.size = 64
    relodyn.purpose = lief.ELF.RELOCATION_PURPOSES.PLTGOT
    print("new relocation uses addend: {}".format(relodyn.is_rela))
    pltgot_relo = binary_to_update.add_pltgot_relocation(relodyn)

    #dyn_relo = binary_to_update.add_dynamic_relocation(relodyn)
    print("Checking that {} exists in pltgot relocations".format(sym.name))
    found=False
    i,x = (None,None)
    for i,x in enumerate(binary_to_update.pltgot_relocations):
        if sym.name == x.symbol.name:
            found=True
            break
    if not found:
        print("ERROR: {} was not inserted into pltgot relocation table")
        raise ValueError
    else:
        print("Found {} [index = {}]".format(x.symbol.name,x.symbol.shndx))
        print("Should have {} entries in .rela.plt".format(
                  len(binary_to_update.pltgot_relocations))
             )
    return pltgot_relo

def add_dynlibrary(binary:lief.Binary,library_name:str):
    print("add_dynlibrary : {}".format(library_name))
    prev_dynentries = binary.dynamic_entries
    for i in prev_dynentries:
       print("=> {}".format(i))
    x= binary.add_library(library_name)
    print("Library added")
    new_dynentries = binary.dynamic_entries
    for i in new_dynentries:
       print("=> {}".format(i))
    return x

def captureSectionInfo(binary:lief.Binary):
    secCap = dict()
    #strtab
    sections = binary.sections
    for x in sections:
        secCap[x.name] = {'name':x.name,'offset':x.offset,
                          'content':bytearray(x.content),
                          'size':x.size,
                          'entry_size':x.entry_size,
                          'name_idx':x.name_idx,
                          'section_ptr':x
                          }
        #print('section name: {}'.format(x.name))
        #print('{} .strtab index: {}'.format(x.name,x.name_idx))
    return secCap
        
def add_fn_to_pltgot(binary:lief.Binary,fn_to_add:str,jump_add:int,section_info:dict):
    print("function to add = {}".format(fn_to_add))
    inserted_symbol = binary.get_symbol(fn_to_add)
    print("inserted_symbol = {}".format(inserted_symbol))
    plt = binary.get_section(".plt")
    pltgot = binary.get_section(".plt.got")
    plt_entrysize=plt.entry_size
    segs = plt.segments
    print("[before] .plt size is {}".format(plt.size))
    print("[before] .plt.got offset is {:x}".format(pltgot.offset))
    for i,x in enumerate(segs):
        binary.extend(x,plt_entrysize)
    binary.extend(plt,plt_entrysize)
    print("[after] .plt size is {}".format(plt.size))
    binary.patch_pltgot(inserted_symbol,jump_add)
    print("[after] .plt.got size is {}".format(pltgot.size))
    print("[after] .plt.got offset is {:x}".format(pltgot.offset))

    

def patch_to_dynlib_func(binary_to_update:lief.Binary,hook_so:str,hook_fn:str,
                         hook_symbol:lief.Symbol, orig_symbol:lief.Symbol):
    print("patch_to_dynlib_func")
    section_info = captureSectionInfo(binary_to_update)
    dynlib = add_dynlibrary(binary_to_update,hook_so)
    renamed_fn,dyn_shndx,dynsym,statsym = add_symbols(binary_to_update,hook_symbol)
    dynrela = add_reladyn(binary_to_update,dynsym,dyn_shndx)
    #TODO
    print("dynrela.address = {:x}".format(dynrela.address))
    # get plt relocation section
    #for i,x in enumerate(binary_to_update.symbols):
    #    print("{} @ {:x} {} {}".format(x.name,x.value,x.type,x.binding))
    #for i,x in enumerate(binary_to_update.dynamic_symbols):
    #    print("[DYN] {} @ {:x} {} {}".format(x.name,x.value,x.type,x.binding))
    #for i,x in enumerate(binary_to_update.sections):
    #    print("{} @ {:x} [file_offset = {:x}]".format(x.name,x.offset,x.file_offset))
    print("dynrela.symbol = {}".format(dynrela.symbol))
    print("dynrela.address = {:x}".format(dynrela.address))
    add_fn_to_pltgot(binary_to_update,hook_fn,dynrela.address,section_info)

    # ----- need to increase section size for 
    #          .plt
    # ---- anything at an address > address(.plt) needs to be moved
    #          .plt.got
     
    #segment_content = bytearray(binary_to_update.sections.segments[0].content)
    #segment_va = binary_to_update.sections.segments[0].virtual_address
    #section_dict = dict()
    #for x in binary_to_update.sections:
    #    section_dict[x.name]={'offset':x.offset,'length':len(x.content),'section':x}
        
    # Need to patch the pltgot
    
    if False:
        # dynarela => need offset to patch_pltgot with hook_fn
        # each PLT entry is 16 bytes
        #   ff 25 <offset to function>
        #   68 <func_num>
        #   e9 <ffff_fff0-16*func_num>
        got_section=binary_to_update.get_section(".got")
        plt_section=binary_to_update.get_section(".plt")
        pltgot_section=binary_to_update.get_section(".plt.got")
    
        #print("got_section.entry_size = {:x}".format(got_section.entry_size))
        #print("got_section.entropy = {}".format(got_section.entropy))
        #print("got_section.link = {}".format(got_section.link))
        #print("got_section.type = {}".format(got_section.type))
        num_dyn_relo = len(binary_to_update.pltgot_relocations)
        func_num = num_dyn_relo
        got_plt_address = got_section.offset - ((8*func_num)+6)
        jump_plt_address = got_plt_address - (8*(func_num-1))
        #print("func_num = {:x}".format(func_num))
        #print("got_plt_address = {:x}".format(got_plt_address))
        #print("jump_plt_address = {:x}".format(jump_plt_address))
        jump_plt_byteaddress = jump_plt_address.to_bytes(4,byteorder='little')
        plt_jump = bytearray.fromhex("ff25")
        plt_jump.extend(jump_plt_byteaddress)
        plt_jump.extend(bytearray.fromhex("68"))
        plt_jump.extend((func_num-1).to_bytes(4,byteorder='little'))
        plt_jump.extend(bytearray.fromhex("e9"))
        plt_jump.extend((~(16*(func_num+1))+1).to_bytes(4,byteorder='little',signed=True))
        binary_to_update.extend(plt_section,len(plt_jump))
    
        print("jump table for function {}".format(func_num))
        print(plt_jump.hex())
        new_plt = bytearray(plt_section.content)
        new_plt.extend(plt_jump)
        print("Orig content for PLT:\n{}".format(new_plt.hex()))
        for i in range(0,func_num):
            offset = (2+i*16)
            print("offset {} [{}]".format(offset,i))
            new_value = new_plt[offset]-8
            print("{:x}  => {:x}  ".format(new_plt[offset],new_value))
            new_plt[offset]=new_value
        new_plt[8]=new_plt[8]-8
        print("New content for PLT:\n{}".format(new_plt.hex()))
            
        
        
        ## let's extend the .plt section
        print("plt_section.size = {}".format(plt_section.size))
        plt_section.size = len(new_plt)
        plt_section.content = new_plt
        print("[updated] plt_section.size = {}".format(plt_section.size))
        
        ## let's extend the .got section
        #print("got_section.size = {}".format(got_section.size))
        #print("got_section.content = {}".format(got_section.content))
        #new_got = bytearray(got_section.content)
        #last_func_offset = 16+(func_num-1)*8
        #new_func_offset = 16+(func_num)*8
        #new_got[new_func_offset]=new_got[last_func_offset]+16
        #new_got[new_func_offset+1]=new_got[last_func_offset+1]
        #new_got.extend((0).to_bytes(8,byteorder="little",signed=True))
        #got_section.size = len(new_got)
        #got_section.content = new_got
        #print("[updated] got_section.size = {}".format(hex(got_section.size)))
        #print("[updated] got_section.content = {}".format(got_section.content))
        
        #dynstr_section=binary_to_update.get_section(".dynstr")
        #content = bytearray(dynstr_section.content)
        ##new_fn_index = content.find(hook_fn.encode())
        ##new_content = content[0:new_fn_index]
        ##new_content.extend(content[new_fn_index+len(hook_fn):-1])
        ##new_content.extend(hook_fn.encode())
        #content.extend(hook_fn.encode())
        #print(type(dynstr_section.content))
        #dynstr_section.content = content
        #dynstr_section.size = len(content)
        ##dynstr_section.content = new_content
        ##dynstr_section.size = len(new_content)
        #print("dynstr.content = {}".format(bytearray(dynstr_section.content).decode()))
            
    
        # need to calculate offset into dynamic library
        #   dynlib.value (virtual address of dynamic library)
        #   hook_symbol.value (virtual address of hook function symbol)
        #orig_symbol = binary_to_update.get_symbol(renamed_fn)
        #dynlib_addr = dynlib.value+orig_symbol.value
        #print("Updating content at address {:x}".format(dynlib_addr))
        #print("hook_symbol.value {:x}".format(hook_symbol.value))
        #print("orig_symbol.value {:x}".format(orig_symbol.value))
        #change_function_to_jump(binary_to_update=binary_to_update,func_name=hook_fn,
        #dest_address=dynlib_addr)
    return binary_to_update,dynlib

def does_segment_exist(binary:lief.Binary,segment_name:str):
    print("Not implemented")
    for x in binary.segments:
       print(x)
    return False    

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
            print("Adding Segment: {}".format(patch_binary.segments[0]))
            segment = binary_to_update.add(patch_binary.segments[0])
        else:
            print("Segment already exists: {}".format(segment))
        
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
    patch_fn_name:str, segment:lief.ELF.Segment=None):
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
    if not their_fn.imported and their_fn.is_function:
        if not segment:
            print("Adding Segment:\n[----- \n {}\n] -----".format(patch_binary.segments[0]))
            patch_segments = patch_binary.segments[0]
            segment = binary_to_update.add(patch_segments)
            #patch_imports = patch_binary.symbols
            # THE FOLLOWING COMMENTED OUT CODE SEGMENT CONTAINS STUFF I WROTE THAT
            #  PATCHED THE ADDED SEGMENT'S PLTGOT, BUT THE PROBLEM WAS THAT WHEN
            #  THE PROGRAM IS LOADED, ALL OFFSETS ARE INCORRECT, BECAUSE THE GOT 
            #  IS UPDATED DURING LOAD -> THIS WON'T WORK 
            #update_reloc = dict()
            #for x in patch_imports:
            #    #print("Symbol: {} [binding : {}] [type: {}] [shndx:{}]".format(
            #    #x.name,x.binding,x.type,x.shndx))
            #    if not x.is_function and x.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL:
            #        print("Updating {} in reloc".format(x.name))
            #        print(" {} ".format(x))
            #        print(" Section: {} ".format(patch_binary.get_section('.plt')))
            #        if binary_to_update.has_symbol(x.name):
            #            if not x.name in update_reloc.keys():
            #                orig_addr = patch_binary.get_relocation(x.name).address
            #                reloc_addr = binary_to_update.get_relocation(x.name).address
            #                update_reloc[x.name] = {'orig':orig_addr,'reloc':reloc_addr}
            #                print("{} @ {} => {}".format(x.name,hex(orig_addr),hex(reloc_addr)))
            #        else:
            #            print("We have a problem. '{}' is imported, but does not exist in original binary".format(x.name))
            #            raise IndexError
            #print(update_reloc)
            #for x in update_reloc:
            #    patch_symbol = patch_binary.get_symbol(x)
            #    print("=================")
            #    print(patch_symbol)
            #    for i,j in enumerate(patch_binary.pltgot_relocations):
            #        print("[patch pltgot relocations] {} ".format(j))
            #        print("info: {}".format(j.info))
            #        #print("section: {}".format(j.section))
            #        print("symbol: {}".format(j.symbol))
            #        print("type: {}".format(j.type))
            #        print("address: {:04x}".format(j.address))
            #        print("is_rel: {}".format(j.is_rel))
            #        print("is_rela: {}".format(j.is_rela))
            #        print("addend: {}".format(j.addend))
            #        print("-------")
            #        
            #    print("!!!! Updating {} to reloc @ {}".format(x,hex(update_reloc[x]['reloc'])))
            #    for i,j in enumerate(patch_segments.sections):
            #        print("[patch] {} @ offset: {:04x}".format(j.name,j.offset))
            #    for i,j in enumerate(segment.sections):
            #        print("segment: {},{}".format(i,j))
            #    #patch_binary.patch_pltgot(x,update_reloc[x])
            #    offset = update_reloc[x]['orig']
            #    bin_offset = update_reloc[x]['reloc']
            #    new_content = binary_to_update.get_content_from_virtual_address(bin_offset,4)
            #    print("ORIGINAL VALUE [{:x}] => {}".format(offset,segment.content[offset:offset+4]))
            #    print("value to write: {:x} => {}".format(bin_offset,new_content))
            #    #segment.content[offset:offset+4]=(newcontent).to_bytes(4,byteorder='little')
            #    binary_to_update.patch_address(segment.virtual_address+offset,new_content)
            #    print("UPDATED VALUE [{:x}] => {}".format(offset,segment.content[offset:offset+4]))
            # for each imported function in the binary patch, update the .got.plt table
            # with address from binary_to_update
            #TODO
        else:
            print("Segment already exists: {}".format(segment))
        
        their_fn = binary_to_update.get_symbol(patch_fn_name)
        print("Using Segment:\n[---- \n {}\n] -----\n@ 0x{:08x}".format(segment,segment.virtual_address))
        print("Segment type is :{}".format(segment.type))
        my_fnsym = patch_binary.get_symbol(patch_fn_name)
        print("Their function symbol [is_function = {}] [is_static = {}] :\n {} @ 0x{:04x}".format(
                their_fn.is_function, their_fn.is_static,
                their_fn,their_fn.value #,fn_segment.virtual_address+their_fn.value
                ))
        fn_segment = binary_to_update.segment_from_virtual_address(their_fn.value)
        print("Their function segment: @ {:04x}".format(fn_segment.virtual_address))
        print("my function segment @ {:04x} + offset {:04x}".format(segment.virtual_address,my_fnsym.value))
        my_fn_addr = segment.virtual_address + my_fnsym.value
        print("Relative offset from their function to patch function : {:04x}".format(my_fn_addr-their_fn.value))
        #binary_to_update.patch_pltgot(patch_fn_name,my_fn_addr)
        renamed_fn = "m"+patch_fn_name
        renamed_fnsym = change_func_name(patch_fn_name,renamed_fn,binary_to_update)
        change_function_to_jump(binary_to_update,func_name=renamed_fn,
                                #dest_address=my_fn_addr)
                                dest_address=(my_fn_addr-their_fn.value))
        #print("{:08x} => relative jump address [seg.VA] {:08x}".format(my_fn_addr,my_fn_addr-fn_segment.virtual_address))
        print("{:08x} => relative jump address [func.value] {:08x}".format(my_fn_addr,my_fn_addr-their_fn.value))
        print("{:08x} => relative jump address [func.value] {:08x} [their function value: {:08x}]".format(my_fn_addr,my_fn_addr-their_fn.value,their_fn.value))
        print("offset {:x} [ virtual address {:08x} ]".format(
                              binary_to_update.virtual_address_to_offset(my_fn_addr),
                              my_fn_addr))
        print("content '{}' @ {:08x} ]".format(
                              bytearray(binary_to_update.get_content_from_virtual_address(segment.virtual_address,28)).hex(),
                              segment.virtual_address))
        print("content '{}' @ {:08x} ]".format(
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
        print("lief.ELF.DYNAMIC_TAGS.FLAGS")
        flags = binary_to_update[lief.ELF.DYNAMIC_TAGS.FLAGS]
        flags.remove(lief.ELF.DYNAMIC_FLAGS.BIND_NOW)
    
    if lief.ELF.DYNAMIC_TAGS.FLAGS_1 in binary_to_update:
        print("lief.ELF.DYNAMIC_TAGS.FLAGS_1")
        flags = binary_to_update[lief.ELF.DYNAMIC_TAGS.FLAGS_1]
        flags.remove(lief.ELF.DYNAMIC_FLAGS_1.NOW)
    
    # Remove RELRO
    if lief.ELF.SEGMENT_TYPES.GNU_RELRO in binary_to_update:
        print("lief.ELF.SEGMENT_TYPES.GNU_RELRO")
        binary_to_update[lief.ELF.SEGMENT_TYPES.GNU_RELRO].type = lief.ELF.SEGMENT_TYPES.NULL

    
    return success,binary_to_update,segment

def inject_hook(inputbin:str,outputbin:str,hook_file:str,override_functions:list):
    # currently developed with assumption that functions being patched exist in input binary image
    # and not an external dynamic shared object/library
    #imported_libs = modifyme.imports
    #lief.Logger.enable()
    #lief.Logger.set_level(lief.LOGGING_LEVEL.DEBUG)
    modifyme = lief.ELF.parse(inputbin)
    #orig_dir = os.path.dirname(os.path.realpath(inputbin))
    #orig_file = os.path.basename(os.path.realpath(inputbin))
    #inputbin=orig_dir+"/tmp."+orig_file
    #modifyme.write(inputbin)    
    #modifyme = lief.ELF.parse(inputbin)
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
        my_fn=None
        their_fn=None
        try:
            #my_fn = hookme.get_section(fn)
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
            success = False
            modified = None
            my_fn = hookme.section_from_virtual_address(my_funcsym.value)
            their_fn = modifyme.section_from_virtual_address(their_funcsym.value)
            if their_funcsym.imported and their_funcsym.is_function:
               print("patching pltgot [imported function]")
               success,modifyme,segment = patch_pltgot_with_added_segment(modifyme,
                                                hookme,
                                                fn,
                                                segment)
            elif their_funcsym.is_function and not their_funcsym.imported:
               success,modifyme,segment = patch_func_with_jump_to_added_segment(modifyme,
                                                hookme,
                                                fn,
                                                segment)

            else:
               print("Adding dynamic lib [local function]")
               modifyme,dynlib = patch_to_dynlib_func(binary_to_update=modifyme,
                                                      hook_so=hook_filename,
                                                      hook_fn=fn,
                                                      hook_symbol=my_funcsym,
                                                      orig_symbol = their_funcsym)
                


    print("Creating output : '{}'".format(outputbin))
    modifyme.write(outputbin)    
    return not success

def main(args):
    fn_list = args.funcs  
    input_fname = args.infile
    fn_fname = args.patchfile
    output_fname = args.outfile
    compiler = args.compiler
    bin_src_dir = args.bindir
    fn_src_dir = args.fndir
    status,fn_fullpath = generatePatchSO(compiler,fn_fname,fn_src_dir)
    if not status:
       print("Successfully compiled '{}'".format(fn_fullpath))
    else:
       print("Could not compile '{}'".format(fn_fullpath))
       import sys
       sys.exit(-1)
   
    bin_fullpath = "{}/{}".format(bin_src_dir,input_fname)
    out_fullpath = "{}/{}".format(default_src,output_fname)
    status = inject_hook(bin_fullpath,out_fullpath,fn_fullpath,fn_list)
    if not status:
       print("Successfully stitched ALL '{}' into '{}' as output '{}'".format(fn_list,input_fname,output_fname))
    chmod_mask = os.stat(bin_fullpath).st_mode & 0o777
    os.chmod(out_fullpath,chmod_mask)




if __name__ == '__main__':
    arguments = parse_arguments()
    main(arguments)
