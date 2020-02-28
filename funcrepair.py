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
debug = False

hook_filename = "libhook.so"

def dprint(*args, **kwargs):
    if debug:
       print(*args, **kwargs)

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

def hookFunctionIsStandalone(hook_binary):
    print("-W- WARNING: Standalone Binary Checking for new function is not implemented!")
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
        print("WARNING: Code being injected is larger than original code")
        print("original size: {}".format(their_funcsym.size))
        print("patch size: {}".format(len(my_code)))
        print("Overrun size: {}".format(len(my_code)-their_funcsym.size))
    return inject_code(binary_to_update,their_funcsym.value,my_code)

def change_function_to_jump(binary_to_update:lief.Binary,func_name:str,dest_address:int):
    #my_function_call = "jmp 0x{}".format(hex(dest_address))
    # this should really be changed to some python library 
    # that converts an assembly instruction to bytearray
    dprint("Original address: {:08x}".format(dest_address))
    #hex_string = bytearray.fromhex("ff25")
    #hex_addr = int(0).to_bytes(4,byteorder='little')
    #hex_string.extend(hex_addr)
    hex_string = bytearray.fromhex("e9")
    # relative address 0+%rip
    hex_addr = (dest_address-5).to_bytes(4,byteorder='little')
    hex_string.extend(hex_addr)
    dprint("JUMP Instruction: {}".format(hex_string))
    my_function_call = hex_string
    #my_function_call.append(dest_address.to_bytes(4,byteorder='big'))
    # this is a placeholder until i get the whole call values 
    return change_function_content(binary_to_update,func_name,my_function_call)

def replaceSymbol(binary:lief.Binary,orig_name:str,new_fn_name):
    orig_symbol = binary.get_symbol(orig_name)
    osymndx = int(orig_symbol.shndx)
    new_symbol = lief.ELF.Symbol()
    dprint("orig symbol   : {} [shndx = {}]".format(orig_symbol,orig_symbol.shndx))
    dprint("default symbol: {} [shndx = {}]".format(new_symbol,new_symbol.shndx))
    new_symbol.name = new_fn_name
    new_symbol.binding = orig_symbol.binding
    new_symbol.type = orig_symbol.type 
    new_symbol.value = orig_symbol.value 
    symbol_version = None
    if orig_symbol.has_version:
        new_symbol.symbol_version = orig_symbol.symbol_version
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
        print("Original symbol's index is: {}".format(orig_symbol.shndx))
        print("New symbol      => {}".format(new_symbol.shndx))
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
            dprint("Adding Segment:\n[----- \n {}\n] -----".format(patch_binary.segments[0]))
            patch_segments = patch_binary.segments[0]
            segment = binary_to_update.add(patch_segments)
        else:
            dprint("Segment already exists: {}".format(segment))
        
        their_fn = binary_to_update.get_symbol(patch_fn_name)
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
        my_fn_addr = segment.virtual_address + my_fnsym.value
        dprint("Relative offset from their function to patch function : {:04x}".format(my_fn_addr-their_fn.value))
        renamed_fn = "m"+patch_fn_name
        renamed_fnsym = change_func_name(patch_fn_name,renamed_fn,binary_to_update)
        change_function_to_jump(binary_to_update,func_name=renamed_fn,
                                dest_address=(my_fn_addr-their_fn.value))
        dprint("{:08x} => relative jump address [func.value] {:08x}".format(my_fn_addr,my_fn_addr-their_fn.value))
        dprint("{:08x} => relative jump address [func.value] {:08x} [their function value: {:08x}]".format(my_fn_addr,my_fn_addr-their_fn.value,their_fn.value))
        dprint("offset {:x} [ virtual address {:08x} ]".format(
                              binary_to_update.virtual_address_to_offset(my_fn_addr),
                              my_fn_addr))
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

def inject_hook(inputbin:str,outputbin:str,hook_file:str,override_functions:list):
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
                                                segment)
            else:
               print("ERROR: {} is not a function in {}".format(fn,inputbin))
               print("\nExiting.\n")
               import sys
               sys.exit(-1);
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
