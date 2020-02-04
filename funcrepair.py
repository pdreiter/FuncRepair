#!/usr/bin/env python3
"""
program: {0}
purpose: extract set of functions from binary and patch with external input file
         currently developed with assumption that functions being patched exist in input binary image
         and not an external dynamic shared object/library
"""

import lief
import argparse
import os
default_cwd=os.path.realpath(".")
default_src=default_cwd



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


def generatePatchSO(compiler,patchfile,working_dir):
    """
    purpose: if --fn provided is a *.c file, compile it into a .so file
    """
    import subprocess,shlex
    if not os.path.exists("{}/{}".format(working_dir,patchfile)):
       print("ERROR: '{}' file does not exist in {}".format(patchfile,working_dir))
       return -1
    
    orig_dir = os.path.dirname(os.path.realpath("."))
    os.chdir(working_dir)
    hook_filename = "hook"
    
    status = -1
    compile_command='{} -nostdlib -nodefaultlibs -fPIC -Wl,-shared {} -o {}'.format(
                    compiler,patchfile,hook_filename)
    try:
       proc= subprocess.Popen(shlex.split(compile_command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
       cout,cerr = proc.communicate()
       status = proc.returncode
    except subprocess.CalledProcessError:
       print("Compile command failed: \n{}\nstdout:\n{}\nstderr:\n{}".format(compile_command,
       "\n".join(cout),"\n".join(cerr)))
       raise
    os.chdir(orig_dir)
    return status,"{0}/{1}".format(working_dir,hook_filename)


def inject_hook(inputbin:str,outputbin:str,hook_file:str,override_functions:list):
    # currently developed with assumption that functions being patched exist in input binary image
    # and not an external dynamic shared object/library
    #imported_libs = modifyme.imports
    lief.Logger.enable()
    lief.Logger.set_level(lief.LOGGING_LEVEL.DEBUG)
    modifyme = lief.parse(inputbin)
    hookme = lief.parse(hook_file)
    if not modifyme:
        print("lief.parse({}) failed for some reason".format(inputbin))
    if not hookme:
        print("lief.parse({}) failed for some reason".format(hook_file))
        raise
    success = True
    for fn in override_functions:
        try:
            my_fn = hookme.get_symbol(fn)
            their_fn = modifyme.get_symbol(fn)
            if their_fn.imported:
                print("Symbol is imported - skipping function {}".format(fn))
                continue
            my_code = hookme.segment_from_virtual_address(my_fn.value) # returns Segment
            added_segment = modifyme.add(segment=my_code)
            print("Hook inserted at VA: 0x{:06x}".format(added_segment.virtual_address))
            new_offset = my_fn.value-my_code.virtual_address
            new_addr = added_segment.virtual_address + new_offset
            print(f"Changing {their_fn.name}!{their_fn.value:x} -> {their_fn.name}!{new_addr:x}")
            their_fn.value = new_addr
        except:
            print("ERROR: Couldn't find function '{}' in '{}'".format(fn,inputbin))
            success = False
            pass
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
