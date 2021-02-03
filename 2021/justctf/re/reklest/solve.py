#!/usr/bin/python3

enc = b'{rewJey\x00bnF\x05B_EnEC\x00RZHnSD\x06nCdbEn]\x01\x01ZBnbR\x05CHL'

dec = b'JCTF{'

key = []

for a, b in zip(enc, dec):
    key.append(a ^ b)

# print(bytes(key))

key = [ 0x31 ] * len(enc)

plain = []
for a, b in zip(key, enc):
    plain.append(a ^ b)

print(bytes(plain))
