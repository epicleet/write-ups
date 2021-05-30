# Lost Exponent

## Challenge analysis

We have a python3 script (encode.py) that encodes the flag into a large sequence of bytes saved in a file (enc). Let's analyze the script. At imports part:

```python
from math import sqrt
from random import seed, shuffle
from lost import e, flag
from itertools import product
from numpy import sign, diff
```

we can see that we have a math challenge (math and numpy) with random parts (random) and unknown data (lost). In the next part we already can see that the random part is not so random, since seed is constant:

```python
seed(6174)
n = int(sqrt(len(flag))) + 2
order = list(product(range(n), repeat=2))
shuffle(order)
order.sort(key=(lambda x: sign(diff(x))))
```

Despite that, `flag` is unknown, so we cannot execute this part even knowing the random generator seed. After we have `n`, the list `order` is made of all the two-element tuples from `0` to `n-1` scrambled and sorted in a way that the first `n*(n-1)/2` elements will the tuples that describe the lower triangular matrix part, the next `n` elements will be the diagonal part, and the last `n*(n-1)/2` elements will be the upper triangular matrix part. Let's continue. Now we have a matrix class definition

```python
class Matrix:
    def __init__(self):
        self.n = n
        self.m = [[0]*n for _ in range(n)]

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix()
        for i in range(n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix()
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k]*other[k, j] for k in range(n))
        return r

    def __pow__(self, power):
        r = self.I()
        for _ in range(power):
            r = r * self
        return r

    def __str__(self):
        return str(self.m)
```

It creates a square null matrix with side size equals to `n` already defined based on flag length. The method `I()` returns the identity matrix of same size. The method `__setitem__(key, value)` receives a two-element tuple `key` and a `value` and set the value of element in row `key[0]` and column `key[1]`. The method `__getitem__(key)` returns the element in row `key[0]` and column `key[1]`. The method `__mul__(other)` returns the default matrix multiplication between `self` and `other`. The method `__pow__(power)` returns result of power `self` to `power`, but, in `O(n)` time complexity, since that, if `power` is high enough, this method must be replaced. At least we have the method `__str__()` that returns the list of lists that defines the matrix in `str` format. Let's continue. At least we have the main part:

```python
if __name__ == '__main__':
    m = Matrix()
    for i, f in zip(order, flag):
        m[i] = ord(f)
    cflag = list(map(str, m ** e))
    mn = max(map(len, cflag))
    mn += mn % 2
    cflag = ''.join(b.zfill(mn) for b in cflag)
    cflag = bytes([int(cflag[i:i+2]) for i in range(0, len(cflag), 2)])

    with open('enc', 'wb') as out:
        out.write(cflag)
```

It 

- Creates a matrix `m`;
- Puts the ascii values of flag characters in the order and positions given by `order` list;
- Calculates `cflag` as the list of `m ** e` elements, where `e` is unknown, each in `str` format;
- Equals all elements size with left leading zeros with the smallest even possible;
- Joins all together in a single large `str`;
- Creates a two-digit integer list made of each consecutive pair of digits, from left to right;
- Converts this integer list in bytes;
- Saves all consecutive bytes in the file `enc`.

## Solving it

First we have to modify `Matrix` class as we need. Here, it was changed in a way that we can create a matrix of any size `n` and the method `__pow__(power)` was changed to `O(log n)` time complexity and to use memorization of results:

```python
class Matrix:
    def __init__(self, n):
        self.n = n
        self.m = [[0] * n for _ in range(n)]
        self.pd = dict()

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix(self.n)
        for i in range(self.n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value
        del self.pd
        self.pd = dict()

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix(self.n)
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k] * other[k, j] for k in range(n))
        return r

    def __pow__(self, n, modulo=None):
        if n == 0:
            return self.I()
        if n == 1:
            return self
        if n not in self.pd:
            n2 = self ** (n >> 1)
            self.pd[n] = n2 * n2
            if n & 1:
                self.pd[n] = self.pd[n] * self
        return self.pd[n]

    def __str__(self):
        return str(self.m)
```

In the main script, first we have to recover giant integers matrix from the file `enc`. The following python3 script does it:

```python
with open('enc', 'rb') as inflag:
    cflag = inflag.read()
nc = len(cflag)
n = int(sqrt(nf)) + 2
n2 = n ** 2
nb = nc // n2

cflag = [int(''.join([str(c).zfill(2) for c in cflag[i:i + nb]]))
         for i in range(0, len(cflag), nb)]
mflag = Matrix(n)
for i in range(n):
    for j in range(n):
        mflag[i, j] = cflag[i * n + j]
```
where `nf` is the flag length, that we do not know, so let's bruteforce it based on some conditions:

```python
if __name__ == '__main__':
    with open('enc', 'rb') as inflag:
        cf = inflag.read()
    nc = len(cf)
    nf = len('CTF-BR{}')+1
    while True:
        print(f'Trying nf = {nf}...')
        n = int(sqrt(nf)) + 2
        n2 = n ** 2
        if nc % n2 != 0:
            nf += 1
            continue
        nb = nc // n2

        cflag = [int(''.join([str(c).zfill(2) for c in cf[i:i + nb]]))
                 for i in range(0, len(cf), nb)]

        if len(cflag) != n2:
            nf += 1
            continue

        mflag = Matrix(n)
        for i in range(n):
            for j in range(n):
                mflag[i, j] = cflag[i * n + j]
```

The first condition is based on the fact that the `encode.py` equals the integers number of digits before writing the file, so the file number of bytes must be multiple of the matrix number of elements (`nc % n2 == 0`). After we recover the integers, the number of them must be of predicted matrix size (`len(cflag) == n2`). There will be other conditions further up. 

Now, when we have the correct `nf`, we will have the correct encoded matrix `mflag` and now we can create the `order` list:

```python
        seed(6174)
        n = int(sqrt(nf)) + 2
        order = list(product(range(n), repeat=2))
        shuffle(order)
        order.sort(key=(lambda x: sign(diff(x))))
```

There must be a reason why `order` to be ordered in this way. If we look at the encoded matrix, we will see that it is lower triangular matrix, what makes us think that the original matrix probably is lower triangular matrix too. This makes it easy to get the "lost exponent" `e`, since the first element of encoded matrix `mf[0,0]` and the first element of original matrix `m[0,0]` are related as the following: `mf[0,0] == m[0,0] ** e`. And we can get `e` from `e = log(mf[0,0], m[0,0])`. We do not know `m[0,0]` but we can bruteforce it quickly:

```python
        pos00 = order.index((0, 0))
        mf00 = mflag[0, 0]
        M = (float('inf'), '', 0)
        for c in charset:
            lg = int(log(mf00, ord(c)))
            M = min(M, (abs(ord(c) ** lg / mf00 - 1), c, lg))
            if M[0] == 0:
                break
        e = M[2]
        flag = 'CTF-BR{' + (nf - 8) * ' ' + '}'
        flag = flag[:pos00] + M[1] + flag[pos00 + 1:]
        print(flag)
        
        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)
```
where `charset` and some related constants are defined by:

```python
charset = string.punctuation + string.digits + string.ascii_letters
ncs = list(map(ord, charset))
cs_lims = (min(ncs), max(ncs))
```

As we were minimizing the error in bruteforce process, the result cannot be exact if `nf` is not correct yet, so let's test another condition:

```python
        if (m ** e)[0, 0] != mflag[0, 0]:
            nf += 1
            continue
```

Now we have (assuming that `nf` is correct) the correct "lost exponent" `e`, so let's continue with the matrix recover. In a lower triangular matrix, each of the encoded matrix elements (`I, J`) depends only on the elements of original matrix that are at most in the line of the treated element (`i<=I`) and at least in the treated element column (`j>=J`). In other words, each element (`I, J`) of encoded matrix depends only on the elements of the sub-matrix (`m[i<=I, j>=J]`) of original matrix.

Knowing that, we can find the entire matrix if we bruteforce each element of original matrix (preferably using binary search) from upper to lower diagonals, in other words, determine the original matrix elements in this order:

```python
[[(0, 0), (1, 1), ..., (n-1, n-1)], 
 [(1, 0), ..., (n-1, n-2)], 
 ..., 
 [(n-2, 0), (n-1, 1)],
 [(n-1, 0)]]
```

Or

```python
[[(k+d, k) for k in range(n-d)] for d in range(n)]
```

Using the following script part:

```python
        for d in range(n):
            for k in range(n-d):
                mp = (k + d, k)
                if mp == (0, 0):
                    continue
                posmp = order.index(mp)
                if posmp < len('CTF-BR{'):
                    continue
                mfmp = mflag[mp]
                if mfmp == 0:
                    continue
                M = (float('inf'), 0)
                beg, end = cs_lims
                m[mp] = beg
                beg = (beg, sign((m ** e)[mp] - mfmp))
                m[mp] = end
                end = (end, sign((m ** e)[mp] - mfmp))
                while True:
                    c = (beg[0] + end[0]) // 2
                    m[mp] = c
                    c = (c, sign((m ** e)[mp] - mfmp))
                    if c[1] == 0:
                        M = c[::-1]
                        break
                    if c[1] == beg[1]:
                        beg = c
                    elif c[1] == end[1]:
                        end = c
                    else:
                        raise Exception('How I am here????')
                m[mp] = M[1]
                flag = flag[:posmp] + chr(M[1]) + flag[posmp + 1:]
                print(flag)
                if flag[nf-1] != '}':
                    break
            if flag[nf-1] != '}':
                break
        if flag[nf-1] != '}':
            nf += 1
            continue
```

In this part we test if the last flag character changes from `'}'` and go to next flag size if it happens. 

Lastly, it is important to verify if the `mflag == m ** e` and in that case, we can print the found flag:

```python
        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)

        if sum(int(a == b) for a, b in zip((m ** e), mflag)) == mflag.n ** 2:
            break

        nf += 1

    print(flag)
```

Putting all together:

```python
from random import seed, shuffle
from itertools import product
from math import sqrt, log
from numpy import sign, diff
from string import punctuation, digits, ascii_letters


charset = punctuation + digits + ascii_letters
ncs = list(map(ord, charset))
cs_lims = (min(ncs), max(ncs))


class Matrix:
    def __init__(self, n):
        self.n = n
        self.m = [[0] * n for _ in range(n)]
        self.pd = dict()

    def __iter__(self):
        for i in range(self.n):
            for j in range(self.n):
                yield self.m[i][j]

    def I(self):
        r = Matrix(self.n)
        for i in range(self.n):
            r[i, i] = 1
        return r

    def __setitem__(self, key, value):
        self.m[key[0]][key[1]] = value
        del self.pd
        self.pd = dict()

    def __getitem__(self, key):
        return self.m[key[0]][key[1]]

    def __mul__(self, other):
        r = Matrix(self.n)
        for i in range(n):
            for j in range(n):
                r[i, j] = sum(self[i, k] * other[k, j] for k in range(n))
        return r

    def __pow__(self, n, modulo=None):
        if n == 0:
            return self.I()
        if n == 1:
            return self
        if n not in self.pd:
            n2 = self ** (n >> 1)
            self.pd[n] = n2 * n2
            if n & 1:
                self.pd[n] = self.pd[n] * self
        return self.pd[n]

    def __str__(self):
        return str(self.m)


if __name__ == '__main__':
    with open('enc', 'rb') as inflag:
        cf = inflag.read()
    nc = len(cf)
    nf = len('CTF-BR{}')+1
    while True:
        print(f'Trying nf = {nf}...')
        n = int(sqrt(nf)) + 2
        n2 = n ** 2
        if nc % n2 != 0:
            nf += 1
            continue
        nb = nc // n2

        cflag = [int(''.join([str(c).zfill(2) for c in cf[i:i + nb]]))
                 for i in range(0, len(cf), nb)]

        if len(cflag) != n2:
            nf += 1
            continue

        mflag = Matrix(n)
        for i in range(n):
            for j in range(n):
                mflag[i, j] = cflag[i * n + j]

        seed(6174)
        n = int(sqrt(nf)) + 2
        order = list(product(range(n), repeat=2))
        shuffle(order)
        order.sort(key=(lambda x: sign(diff(x))))

        pos00 = order.index((0, 0))
        mf00 = mflag[0, 0]
        M = (float('inf'), '', 0)
        for c in charset:
            lg = int(log(mf00, ord(c)))
            M = min(M, (abs(ord(c) ** lg / mf00 - 1), c, lg))
            if M[0] == 0:
                break
        e = M[2]
        flag = 'CTF-BR{' + (nf - 8) * ' ' + '}'
        flag = flag[:pos00] + M[1] + flag[pos00 + 1:]
        print(flag)

        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)

        if (m ** e)[0, 0] != mflag[0, 0]:
            nf += 1
            continue

        for d in range(n):
            for k in range(n-d):
                mp = (k + d, k)
                if mp == (0, 0):
                    continue
                posmp = order.index(mp)
                if posmp < len('CTF-BR{'):
                    continue
                mfmp = mflag[mp]
                if mfmp == 0:
                    continue
                M = (float('inf'), 0)
                beg, end = cs_lims
                m[mp] = beg
                beg = (beg, sign((m ** e)[mp] - mfmp))
                m[mp] = end
                end = (end, sign((m ** e)[mp] - mfmp))
                while True:
                    c = (beg[0] + end[0]) // 2
                    m[mp] = c
                    c = (c, sign((m ** e)[mp] - mfmp))
                    if c[1] == 0:
                        M = c[::-1]
                        break
                    if c[1] == beg[1]:
                        beg = c
                    elif c[1] == end[1]:
                        end = c
                    else:
                        raise Exception('How I am here????')
                m[mp] = M[1]
                flag = flag[:posmp] + chr(M[1]) + flag[posmp + 1:]
                print(flag)
                if flag[nf-1] != '}':
                    break
            if flag[nf-1] != '}':
                break
        if flag[nf-1] != '}':
            nf += 1
            continue

        m = Matrix(n)
        for i, f in zip(order, flag):
            m[i] = ord(f)

        if sum(int(a == b) for a, b in zip((m ** e), mflag)) == mflag.n ** 2:
            break

        nf += 1

    print(flag)
```

Running it, after 40 minutes, we have:

```text
Trying nf = 9...
Trying nf = 10...
Trying nf = 11...
Trying nf = 12...
Trying nf = 13...
Trying nf = 14...
Trying nf = 15...
Trying nf = 16...
Trying nf = 17...
Trying nf = 18...
Trying nf = 19...
Trying nf = 20...
Trying nf = 21...
Trying nf = 22...
Trying nf = 23...
Trying nf = 24...
Trying nf = 25...
CTF-BR{                0}
CTF-BR{                06
Trying nf = 26...
CTF-BR{                0 }
CTF-BR{                06}
CTF-BR{                06}
CTF-BR{              _ 06}
CTF-BR{              _106}
CTF-BR{s             _106}
CTF-BR{s           1 _106}
CTF-BR{s  3        1 _106}
CTF-BR{s  3 0      1 _106}
CTF-BR{s  3 0     r1 _106}
CTF-BR{s  3 0F    r1 _106}
CTF-BR{s  3_0F    r1 _106}
CTF-BR{s  3_0F m  r1 _106}
CTF-BR{s M3_0F m  r1 _106}
CTF-BR{s M3_0F_m  r1 _106}
CTF-BR{s0M3_0F_m  r1 _106}
CTF-BR{s0M3_0F_m 7r1 _106}
CTF-BR{s0M3_0F_m 7r1X_106}
CTF-BR{s0M3_0F_m47r1X_106}
CTF-BR{s0M3_0F_m47r1X_106}
```