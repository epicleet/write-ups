from pwn import *
import string
import gmpy2
from math import ceil, sqrt

p = process("julia chall.jl", shell=True)
#p = remote("104.155.185.135", 1337)
res = p.recvuntil("5- Exit")

p.sendline("1")
res = p.recvuntil("5- Exit")
p.sendline("1")
res = p.recvuntil("5- Exit")
p.sendline("1")
res = p.recvuntil("5- Exit")
p.sendline("1")
res = p.recvuntil("5- Exit")

p.sendline("3")
q = int(p.recvuntil("5- Exit").split(b"q = ")[1].split(b"\n")[0])
g = 2

def d_log(h, g, q, m=127*40):
    N = ceil(sqrt(m))
    tbl = {pow(g, i, q): i for i in range(N)}
    c = pow(g, N * (q - 2), q)
    for j in range(N):
        y = (h * pow(c, j, q)) % q
        if y in tbl:
            return j * N + tbl[y]

    return None

def get_encryption(idx):
    p.sendline("4")
    res = p.recvuntil("encrypt?")
    p.sendline(str(idx))
    res = p.recvuntil("5- Exit")
    c, d = map(int, res.split(b" (")[1].split(b")")[0].split(b", "))
    return c, d

def set_secret(secret):
    p.sendline("2")
    res = p.recvuntil("secret:")
    p.sendline(bytes(secret))
    res = p.recvuntil("5- Exit")

def prod(l, q):
    res = 1
    for v in l:
        res = (res * v) % q
    return res


secret =[0]*40
set_secret(secret)
cs = []
ds = []
for i in range(40):
    c, d = get_encryption(i + 1)
    cs.append(c)
    ds.append(d)

flag = ""
for i in range(40):
    min_all_chars = 127*40
    cur_char = '0'
    for b in string.printable:
        secret[i] = ord(b)
        set_secret(secret)
        c, d = get_encryption(i + 1)
        cs_guess = cs[:i] + [c] + cs[i+1:]
        ds_guess = ds[:i] + [d] + ds[i+1:]

        h = prod(cs_guess, q) * gmpy2.invert(prod(ds_guess, q), q) % q
        sum_all_chars = d_log(h, g, q)
        if sum_all_chars < min_all_chars:
            min_all_chars = sum_all_chars
            cur_char = b
    flag += cur_char
    print(flag)
