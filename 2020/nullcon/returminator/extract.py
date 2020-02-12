from pwn import *

p = process('./main')

gdb.attach(p, '''
        break * 0x00000000004012a6
        continue
        ''')

data = open('extract/32', 'rb').read()

p.sendafter(b'!\n', data)

p.interactive()
