#!/usr/bin/env python3

# Stage A: Evaluated individual functions, f for all F (function set)
#    A-1. decompile function f into D
#    A-2. insert inline ASM if D recompiles, else continue
#    A-3. check for test-case equivalency, if valid, add f to VALID_D
# Stage B: Generate PRD decompile source for VALID_D
#    B-1. decompile VALID_D, D'
#    B-2. insert inline ASM if D' recompiles, else FAIL
#    B-3. check for test-case equivalency, if valid SUCCESS, else FAIL


# inputs required:
#   1. Binary Image
#   2. Tests
#   3. PRD build infrastructure
#       a. Copy Makefile.prd from $PRD_BASE_DIR/tools/templates
#       b. Run "make hook funcinsert" using GCC-8

