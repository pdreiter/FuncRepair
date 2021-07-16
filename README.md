# FuncRepair
function-based PRD (Partial Recompilation and Binary Rewriting) scripts for use with BinREPARED (a binary Automated Program Repair Framework)

For PRD decompilation support, see git submodule `genprog_recompilation`

## How to set up
`source init.bash` 
* This sets up a python virtual environment that ensures that both the Python2 and Python3 requirements for the cb-multios (Linux) version of the DARPA CGC Challenge Binaries are installed
  * python3-ported versions of cb-multios scripts are located at:
  	* tools/cb-multios
* This clones/downloads ancillary repos/tarballs and prepares them for use with BinREPARED
  * glibc 2.31 source (reference content)
  * dietlibc (lightweight libc alternative)
  * cb-multios
  * APR
  	* GenProg for BinREPARED 
		* available as git submodule
  	* Prophet for BinREPARED
		* requires manual updates to official tar.gz image
		* see tools/apr/prophet/README.md
		* all provided scripts were tested with PRD with cb-multios

