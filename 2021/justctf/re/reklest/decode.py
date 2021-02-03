#!/usr/bin/python3

from struct import pack
from base64 import b64decode

p64 = lambda x : pack("<Q", x)

a = [0x0A884DF8AB2FBC902, 0x0E0D28ACBFB46461A, 0x6178F0BE4CD508AC, 0x603AD81291B66724, 0x0DE5CDDE19279A148, 0x70E60361F80E8EB4]
b = [0xD8BDEEE9C2938E66, 0xD598D291C97F7779, 0xD32C3E736983BF4, 0xC428F73FC8F2140, 0xA419A7AFE834F505, 0x4DAB6D008D6DF4F9]

r = b''

for x, y in zip(a, b):
    r += p64(x ^ y)

print(r)

decoded = b64decode(r)
print(decoded)
