hidE
===

This RSA encryption service is so secure we're not even going to tell you how we encrypted it

`nc be.ax 31124`

Downloads

- [main.py](https://static.cor.team/uploads/2285a60dd5349ab843e68d34273849e6426817cea84df9421f6189537c64bdee/main.py)

Task analysis
===

The challange gave the script running in server (`main.py`):

```python
#!/usr/local/bin/python
import random
import time
import math
import binascii
from Crypto.Util.number import *

p, q = getPrime(512), getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)

flag = open('./flag.txt').read().encode()

random.seed(int(time.time()))

def encrypt(msg):
    e = random.randint(1, n)
    while math.gcd(e, phi) != 1:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()


def main():
    print('Secure Encryption Service')
    print('Your modulus is:', n)
    while True:
        print('Options')
        print('-------')
        print('(1) Encrypt flag')
        print('(2) Encrypt message')
        print('(3) Quit')
        x = input('Choose an option: ')
        if x not in '123':
            print('Unrecognized option.')
            exit()
        elif x == '1':
            print('Here is your encrypted flag:', encrypt(flag))
        elif x == '2':
            msg = input('Enter your message in hex: ')
            print('Here is your encrypted message:', encrypt(binascii.unhexlify(msg)))
        elif x == '3':
            print('Bye')
            exit()

if __name__ == '__main__':
    main()
```

Basically two 512-bit primes are generated (`p` and `q`), `n = p*q` and `phi = (p-1)*(q-1)` are set, the `flag` is loaded from file and **the random generator is initialized with `time.time()` as seed**. This seed make possible to us to solve the challenge, since we can bruteforce it (let's back here after).

When we connect to server, there is a menu when we can choose between encrypt the flag or encrypt a known message. For both of them, it is used the same function to encrypt:

```python
def encrypt(msg):
    e = random.randint(1, n)
    while math.gcd(e, phi) != 1:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()
```

See that there is only one of the variables that is random (`e`) and that if `gcd(e, phi) == 1` at first time, we don't need `phi` to encrypt any message locally. We don't know `phi` but we know it is necessarily divisible by 2. A random odd `e` and an even `phi` have a great chance to be coprimes.

Solving the Challenge
===

Let's start by getting the `seed`. One way to do so is setting the `seed` as te epoch time before connect the server, encrypt one known message using server and try `seed`'s sequentially until the locally encrypted known message results in the same ciphertext as the message encrypted in the server (assuming only that `phi` is even), so let's use the following encrypt function:

```python
def encrypt(msg, n):
    e = random.randint(1, n)
    while e % 2 == 0:
        e = random.randint(1, n)
    pt = bytes_to_long(msg)
    ct = pow(pt, e, n)
    return binascii.hexlify(long_to_bytes(ct)).decode()
```

And this script to find the `seed`:

```python
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
```

As we are assuming that the only possible common factor between `e` and `phi` is 2, sometimes we won't find the `seed`. To avoid this situation, if it takes more than 10 seconds to find the `seed`, the connection is closed and it tries again.

Found the `seed`, now we can encrypt the flag using the server to get the ciphertext and get the cooresponding `e` using the `seed` locally. 

But how can we find the `flag` given the ciphertext and the `e` if we didn't factorize `n`? That is possible because we know that the original message is the same and the `n` is the same, so we can use the [Common Modulus Attack](https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5). Let's see how it works.

First we have to obtain two versions of encrypted flag and the `e` for each of them, so that the `e`'s are coprimes:

```python
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
```

After we must find `a` and `b` such that `a * e1 + b * e2 == 1` using the extended GCD algorithm:

```python
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
```

After we have `a` and `b`, the flag can be determined with `m == (c1 ** a * c2 ** b) % n`, but one of them will be negative:

```python
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
```

It was important to check if the flag was found because of the `e` and `phi` relation discussed before. Now we have the full solver:

```python
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
    assert gcd(e1, e2) == 1
    a, b = extended_gcd(e1, e2)
    if a < 0:
        print('a < 0')
        cflag1 = inverse(cflag1, n)
        a = -a
    assert a > 0
    if b < 0:
        print('b < 0')
        cflag2 = inverse(cflag2, n)
        b = -b
    assert b > 0
    flag = long_to_bytes((pow(cflag1, a, n)*pow(cflag2, b, n)) % n)
    if b'corctf' in flag:
        print(flag)
        break
    conn.close()
```

Running it, after at most a few tries:

```
corctf{y34h_th4t_w4snt_v3ry_h1dd3n_tbh_l0l}
```




