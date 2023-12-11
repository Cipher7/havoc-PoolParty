#!/usr/bin/env python
#Author : Cipher007

from havoc import Demon, RegisterCommand, RegisterModule
import os


cwd = os.getcwd()
listener = ""
shellcode_file_path = cwd + "/payload.bin"

def generate64(demonID, *param):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)

	TaskID = demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating x64 payload for PoolParty!")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Saving the payload to file")

	return TaskID

def generate32(demonID, *param):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)

	TaskID = demon.ConsoleWrite(demon.CONSOLE_INFO, "Generating x86 payload for PoolParty!")

	demon.ConsoleWrite(demon.CONSOLE_INFO, "Saving the payload to file")
	return TaskID

def save_shellcode(data):
	with open(shellcode_file_path, "wb") as file:
		file.write(b64decode(data))
	file.close()

RegisterModule("poolparty", "Windows Thread Pool Injection Module", "", "", "", "")
RegisterCommand(generate64, "poolparty", "gen64", "Generate the demon payload using x64 shellcode",0, "", "")
RegisterCommand(generate32, "poolparty", "gen32", "Generate the demon payload using x86 shellcode",0, "", "")