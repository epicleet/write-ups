# This code is pretty slow... :(
from Crypto.Util.number import long_to_bytes
from pwn import *
import re

def readMatrix(file):
    contents = open(file, 'r').read().replace(' ', ',')
    fim = ""
    for line in contents.split("\n"):
        fim += "".join([str(k) for k in [int(x) for x in re.findall('\d+',line)]])
    return long_to_bytes(int(fim, 2))

AT = readMatrix('PkeyA')
BT = readMatrix('PkeyB')
CT = readMatrix('PkeyC')
DT = readMatrix('PkeyD')
Q = readMatrix('PkeyQ')

fp = open('pk', 'wb')
fp.write(AT + BT + CT + DT + Q)
fp.close()

p = process(['./a.out'])
print(p.recvall())
