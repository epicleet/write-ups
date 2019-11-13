There were two files in this challenge. The data file (crypt) is made of many big integer numbers. Let's analyze the binary (randCrypt). If we decompile it in pseudocode, it is very easy to understand:

```c
  v3 = fopen(flag, modes);
  v14 = fread(file, 1uLL, (size_t)&unk_3B9AC9FF, v3);
  fclose(v3);
  cfile = malloc(48LL * v14);
  for ( i = 0; i < v14; ++i )
    bi::set((bi *)((char *)cfile + 16 * i), file[i]);
```

This first *for*, with *bi::set* just sets the bytes of flag file to an *bi* type variable. If we explore *bi::set* we will see that is is an structure using *gmpz* functions, that is, an structure for big integers operations. *v14* is the number of bytes inside file.

```c
  v4 = time(0LL);
  srand(v4);
  v19 = rand() % 4011;
```

Now a random variable (the number of iterations) is setted.

```c
  for ( j = 0; j < v19; ++j )
  {
```

For each iteration, at first it is verified if the number of *cfile* elements is odd. If so it is added a new element at end. After the *if* the size of *cfile* will be even.

```c
    printf(&modes[3], (unsigned int)j, (unsigned int)v19);
    if ( v14 & 1 )
    {
      v5 = v14++;
      bi::operator=((char *)cfile + 16 * v5, 0LL);
    }
```

Now for each pair of consecutive elements from *cfile* (always even and odd indices, respectively), the first one is replaced by their sum and the second one is replaced by the subtraction

```c
    for ( k = 0; k < v14; k += 2 )
    {
      v6 = bi::operator+(
             (char *)cfile + 16 * k,
             *((_QWORD *)cfile + 2 * (k + 1LL)),
             *((_QWORD *)cfile + 2 * (k + 1LL) + 1));
      v8 = v7;
      *(_QWORD *)&v9 = bi::operator-(
                         (char *)cfile + 16 * k,
                         *((_QWORD *)cfile + 2 * (k + 1LL)),
                         *((_QWORD *)cfile + 2 * (k + 1LL) + 1));
      v10 = (__int64 *)((char *)cfile + 16 * k);
      *v10 = v6;
      v10[1] = v8;
      *((_OWORD *)cfile + k + 1LL) = v9;
    }
```

At end of an iteration an odd index is randomly chosen and its least significant bit is changed, that is, if the chosen number was even it becomes odd and if odd it becomes even.

```c
    v11 = (char *)cfile;
    v12 = rand();
    bi::operator^=(&v11[16 * (v12 % v14 | 1)], 1LL);
  }
```

At program end the resulting numbers are written in the data file given in reversed order.

```c
  stream = fopen(crypt, off_10EE);
  for ( l = 0; l < v14; ++l )
    __gmp_fprintf(stream, &off_10EE[3], (char *)cfile + 16 * (v14 - 1 - l));
  fclose(stream);
  free(cfile);
```

Now we understand the binary it is important to remember that when we sum and subtract two integer numbers, both results have sme parity, so iterating from end to beginning, the unique pair with two distinct parities are the wrong one and the element of odd index must be changed. 

There are two ways to identify where to stop iterating:

- All bytes in byte values interval (0 to 255 decimal)
- Using statistics, that is, it is extremely unlikely that exactly one pair of elements have different parities in original file.

The following script in python3 (copied from solve.py) solves the challenge using the second method:

```python
def pair(n):
    return n & 1 == 1


if __name__ == "__main__":
    with open('crypt') as fp:
        lst = list(map(int, fp.read().strip().split()))[::-1]

        while True:
            while lst[-1] == 0:
                lst = lst[:-1]
            if len(lst) % 2 == 1:
                lst.append(0)
            ndiff, idiff = 0, -1
            for i in range(0, len(lst), 2):
                if pair(lst[i]) != pair(lst[i+1]):
                    ndiff += 1
                    idiff = i+1
            if ndiff > 1:
                break
            lst[idiff] ^= 1
            for i in range(0, len(lst), 2):
                lst[i], lst[i+1] = (lst[i]+lst[i+1])//2, (lst[i]-lst[i+1])//2

    while lst[-1] == 0:
        lst = lst[:-1]

    with open('FLAG', 'wb') as fp:
        fp.write(bytes(lst))
```

When we run it, the file FLAG is created. It is a png file. Opening it we have:

![](https://i.ibb.co/jg7t85G/flag.png)
