from pwn import *
from base64 import b64encode

context.log_level = 'DEBUG'

def resolve_64(binary):
    data = open(binary, 'rb').read()
    size = ord(data[0x819:0x81a])
    char = data[0x820:0x821]
    tail = data[0x1010:0x1018]

    return char * size + tail

def resolve_32(binary):
    data = open(binary, 'rb').read()
    size = ord(data[0x661:0x662])
    char = data[0x668:0x669]
    tail = data[0x1008:0x100c]

    return char * size + tail


def resolve(binary):
    print(binary)
    elf = ELF(binary)
    if elf.elfclass == 64:
        return resolve_64(binary)
    return resolve_32(binary)

p = remote('re.ctf.nullcon.net', 1234)

for _ in range(100):
    binary = p.recvline().strip().decode()

    solution = resolve(binary)
    # print(solution)

    p.sendlineafter(b'> ', b64encode(solution))

    p.recvline()
