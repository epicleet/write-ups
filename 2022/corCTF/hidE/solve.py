from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from math import gcd


def extended_gcd(x, y):
    # a*x + b*y = 1
    a = 0
    b = 1
    lasta = 1
    lastb = 0
    while y != 0:
        quo = x // y
        x, y = y, x % y
        a, lasta = lasta - quo * a, a
        b, lastb = lastb - quo * b, b
    return lasta, lastb


def encrypt(msg, n):
    e = random.randint(1, n)
    while e % 2 == 0:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()


while True:
    prox = False
    seed = int(time.time())
    conn = remote('be.ax', 31124)
    data = conn.recvuntil(b'option: ').decode()
    n = int(re.search(r'is: (\d+)', data).group(1))
    print('n =', n)
    conn.sendline(b'2')
    txt = b'aa'
    conn.sendlineafter(b'hex: ', txt)
    data = conn.recvline().decode()
    print(data)
    ctxt = re.search(r'message: ([0-9a-f]+)', data).group(1)
    random.seed(seed)
    enc = encrypt(binascii.unhexlify(txt.decode()), n)
    t0 = time.time()
    while enc != ctxt:
        seed += 1
        random.seed(seed)
        enc = encrypt(binascii.unhexlify(txt.decode()), n)
        if time.time() - t0 > 10:
            prox = True
            break
    if prox:
        conn.close()
        continue
    random.seed(seed)
    encrypt(binascii.unhexlify(txt.decode()), n)
    e2 = e1 = random.randint(1, n)
    conn.recvuntil(b'option: ')
    conn.sendline(b'1')
    data = conn.recvline().decode()
    cflag2 = cflag1 = bytes_to_long(bytes.fromhex(re.search(r'flag: ([0-9a-f]+)', data).group(1)))
    while gcd(e1, e2) != 1:
        conn.recvuntil(b'option: ')
        conn.sendline(b'1')
        data = conn.recvline().decode()
        cflag2 = bytes_to_long(bytes.fromhex(re.search(r'flag: ([0-9a-f]+)', data).group(1)))
        e2 = random.randint(1, n)
        while e2 % 2 == 0:
            e2 = random.randint(1, n)
    a, b = extended_gcd(e1, e2)
    if a < 0:
        print('a < 0')
        cflag1 = inverse(cflag1, n)
        a = -a
    if b < 0:
        print('b < 0')
        cflag2 = inverse(cflag2, n)
        b = -b
    flag = long_to_bytes((pow(cflag1, a, n)*pow(cflag2, b, n)) % n)
    if b'corctf' in flag:
        print(flag)
        break
    conn.close()
