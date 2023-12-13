# havoc-PoolParty

Havoc Extension to a PoC Windows Thread Pool Injection created by [Alon Leviev](https://twitter.com/_0xDeku)

PoC Github: https://github.com/SafeBreach-Labs/PoolParty


#### generate.py - Custom PoolParty.exe generator script (Max payload size: 200k)


## PoolParty Variants

| Variant ID  | Varient Description | Status |
| ------------- | ----------------- | ---------- |
| 1  | Overwrite the start routine of the target worker factory       | (IN PROGRESS)|
| 2  | Insert TP_WORK work item to the target process's thread pool   | (IN PROGRESS)|
| 3  | Insert TP_WAIT work item to the target process's thread pool   | (IN PROGRESS)|
| 4  | Insert TP_IO work item to the target process's thread pool     | READY |
| 5  | Insert TP_ALPC work item to the target process's thread pool   | READY |
| 6  | Insert TP_JOB work item to the target process's thread pool    | READY |
| 7  | Insert TP_DIRECT work item to the target process's thread pool | READY |
| 8  | Insert TP_TIMER work item to the target process's thread pool  | READY |


## Installation

Can be installed directly through Havoc Extensions.

OR

- Clone this repository
- Modify the current working directory in poolparty.py
- Import poolparty.py into Havoc


## Usage

### Generate payload

poolparty generate -a {x86/x64} -l {listener name}

### Injection 

poolparty run -V {4,5,6,7,8} -P {PID}

## Screenshots

![Havoc](https://raw.githubusercontent.com/Cipher7/havoc-PoolParty/main/havoc-poolparty.png?token=GHSAT0AAAAAACBATHT5KKC3SW7TEGM3PG4OZLZXMVA)

## Credits

My good friend [0xEr3bus](https://twitter.com/0xEr3bus) for having patience :)

Check out his BOF implementation : https://github.com/0xEr3bus/PoolPartyBof
