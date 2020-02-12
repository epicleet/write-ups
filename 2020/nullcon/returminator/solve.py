from z3 import *

flag = [ BitVec('char_%d' % (i, ), 16) for i in range(35) ]

s = Solver()

for c in flag:
    s.add(c >= 0x20, c < 0x7f)

r = [208, 225, 237, 20, 214, 183, 79, 105, 207, 217, 125, 66, 123, 104, 97, 99, 107 , 105, 109, 50, 48, 202, 111, 111, 29, 63, 223, 36, 0, 124, 100, 219, 32]

rets = [
    flag[0] + flag[2] + flag[4] - 0x64,
    flag[6] + flag[8] + flag[0xa],
    flag[0xc] + flag[0xe] + flag[0x10],
    flag[0x12] + flag[1] - flag[0x1e],
    flag[3] + flag[0x16] + flag[3] - 0x64,
    flag[5] + flag[0x1d] + flag[0x1c] - flag[7] - 0x64,
    flag[9] + flag[0x11] - flag[0xb],
    flag[0xd] + flag[0xf] + flag[0x14] - flag[0x13] - flag[0x1b],
    flag[0x15] + flag[0x17] + flag[0x17],
    flag[0x19] + flag[0x1a],
    flag[0x1e],
    flag[9],
    flag[8],
    flag[0],
    flag[1],
    flag[2],
    flag[3],
    flag[4],
    flag[5],
    flag[6],
    flag[7],
    flag[0xb] + flag[0],
    flag[0x1d],
    flag[0x1d],
    flag[0x1d] - flag[0xd],
    flag[0x1c] - flag[0xe],
    flag[0x1c] + flag[0xf],
    flag[0] - flag[0x1b],
    flag[0x17] - flag[0x18],
    flag[0x1a] + flag[0] - flag[1],
    flag[0x13],
    flag[0xb] + flag[0xc],
    flag[0x15] - flag[0x14],
]

for a, b in zip(r, rets):
    s.add(a == b)

if s.check() == sat:
    m = s.model()
    print(bytes([ int('%r' % (m[c], )) for c in flag]))
