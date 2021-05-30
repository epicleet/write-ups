from fastecdsa import curve, point
import math
import gmpy2
import sympy
import pickle
import os
from pwn import *
from tqdm import tqdm

E = curve.P256

q1 = 2 * 2 * 2 * 2 * 3 * 71 * 131 * 373 * 3407
q2 = 17449 * 38189 * 187019741 * 622491383 * 1002328039319 * 2624747550333869278416773953
q = q1*q2 + 1

# Solver with baby step giant step:
m = math.ceil(math.sqrt(q1)) 
table = {}
base = pow(7, q2, q)

if os.path.isfile('ec_table'):
    with open("ec_table", "rb") as f:
        table = pickle.load(f)
else:
    t = 1
    print("Creating table...")
    for j in tqdm(range(m)):
        table[(t*E.G).x] = j
        t = t * base % q
    with open("ec_table", "wb") as f:
        pickle.dump(table, f)

v = gmpy2.powmod(base, -m, q)

# p = process("./run.py", shell=True)
p = remote('t00-rare.pwn2win.party', 1337)
res = p.recvline()
p2 = process(res, shell=True)
token = p2.recvline().split(b" ")[2]
p.sendline(token)

res = p.recvuntil("4- Exit")
p.sendline("3")
p.recvuntil("password: ")
p.sendline("123")
res = p.recvuntil("4- Exit").decode().split("...")[0].split("Signing ")[1]
h = int(res, 16)
hh = q + h
p.sendline("1")
p.recvuntil("hash (hex): ")
p.sendline(hex(hh)[2:])

res = p.recvuntil("4- Exit").decode().split(")")[0].split("(")[1].split(", ")
r = int(res[0])
s = int(res[1])

print(r, s, h)

rx = r
ry = sympy.sqrt_mod((rx * rx + E.a) * rx + E.b, E.p)

R1 = point.Point(rx, ry, curve=E)
R2 = point.Point(rx, -ry % E.p, curve=E)

P1 = int(gmpy2.invert(r, q))*(s*R1 - h*E.G)
P2 = int(gmpy2.invert(r, q))*(s*R2 - h*E.G)
keys = [P1, P2]

print("Searching...")
flag = None
for i in tqdm(range(m)):
    for j in range(len(keys)):
        if keys[j].x in table:
            d = None
            e = gmpy2.powmod(base, i*m + table[keys[j].x], q)
            eG = int(e)*E.G
            if P1 == eG or P2 == eG:
                print("Found", e)
                d = e
            else:
                if -P1 == eG or -P2 == eG:
                    f = -e % q
                    print("Found", f)
                    d = f
            if d:
                u = gmpy2.invert(s, q)*(r*d + h) % q
                sol1 = gmpy2.invert(u, q)
                sol2 = -sol1 % q
                print(sol1, sol2)
                for sol in [sol1, sol2]:
                    p.sendline("3")
                    p.recvuntil("password: ")
                    p.sendline(str(sol))
                    res = p.recvline()
                    res = p.recvline()
                    print(res)
                    if b'CTF-BR{' in res:
                        flag = res
                        break
        keys[j] = int(v)*keys[j]
    if flag:
        break
assert flag is not None
print("OK!")
p.sendline("4")
res = p.recvuntil("Bye!")
print(res)
