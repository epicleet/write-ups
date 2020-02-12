from pwn import *
from rev import *

context.log_level = 'debug'

p = remote('crypto1.ctf.nullcon.net', 5000)

def which_move(xores):
    if 2 in xores and 3 in xores:
        return b'p'
    if 1 in xores and 2 in xores:
        return b'r'
    return b's'

def my_move(other):
    if other == b'r':
        return b'p'
    if other == b'p':
        return b's'
    return b'r'

for _ in range(20):
    p.recvuntil(b'move: ')
    one, two, three = p.recvline().strip().split(b' ')
    print(one)
    print(two)
    print(three)

    b_one = dehash(one.decode().zfill(32))
    b_two = dehash(two.decode().zfill(32))
    b_three = dehash(three.decode().zfill(32))

    other = which_move((b_one ^ b_two, b_one ^ b_three))

    my = my_move(other)

    p.sendlineafter(b'move:', my)

p.recvuntil(b'win\n')
print(p.recvline())
