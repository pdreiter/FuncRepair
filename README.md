# FuncRepair
function-based Binary Rewriting scripts for use with BinREPARED (a binary Automated Program Repair Framework)

## How to set up
`source init.bash` 
* This sets up a python virtual environment that ensures that Python2 and Python3 requirements for the cb-multios (Linux) version of the DARPA CGC Challenge Binaries are installed
* This clones/downloads ancillary repos/tarballs and prepares them for use with BinREPARED
  * glibc 2.31 source (reference content)
  * dietlibc (lightweight libc alternative)
  * GenProg for BinREPARED
  * cb-multios-prd (cb-multios for BinREPARED)
