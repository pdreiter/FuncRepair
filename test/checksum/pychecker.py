#!/usr/bin/env python3

from ctypes import *
import sys

def checksum(inputstr:str):
	msum=c_byte(-1)
	for x in inputstr:
		x=c_byte(ord(x))
		msum=c_byte(msum.value + x.value)
	return msum.value

   
stdin=sys.argv[1]
mychecksum=checksum(stdin)

valid="checksum({}) = {}".format(stdin,mychecksum)
print(valid)
