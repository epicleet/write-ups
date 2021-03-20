#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
context.log_level = 'debug'

exe = ELF('algorithm')

p = process(exe.path)
if args.GDB:
    gdb.attach(p, '''
        brva 0x24f0
        break * exit
        continue
        ''')

pairs = [(4, 5), (5, 6), (6, 7), (7, 8), (8, 9)]

p.sendlineafter(b'number:\n', b'5')

p.recvuntil(b'numbers:\n')

for a, b in pairs:
    p.sendline(f'{a} {b}'.encode())

p.interactive()
