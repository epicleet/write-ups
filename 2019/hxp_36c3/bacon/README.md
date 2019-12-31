# bacon

Please hack. [vuln.py](vuln.py)

**Total solves:** 38

**Score:** 213

**Categories:** Cryptography


## Challenge

The challenge defines the following hash function, constructed employing the [Speck](https://nsacyber.github.io/simon-speck) block cipher.

```python
def H(m):
    s = bytes(6)
    v = m + bytes(-len(m) % 9) + len(m).to_bytes(9,'big')
    for i in range(0,len(v),9):
        s = Speck(v[i:i+9], s)
    return s
```

The challenge then chooses a random `h` and asks for a preimage attack, i.e., find the value `s` such that `H(s) == h`.

## Solution

We have found [some discussion](https://arxiv.org/pdf/1902.03040.pdf) regarding collisions on Speck-based hash functions. However, we found no shortcuts for a preimage attack.

Since the hash value was small (only 6 bytes), we decided to bruteforce the input. However, we needed to optimize the computation.

For messages consisting of a single block (9 bytes), we can simplify hash computation as follows:

`H(m) == Speck(len(m), Speck(m, 0))`

However `Speck` is a block cipher, which possesses a decryption function `InvSpeck`:

`InvSpeck(len(m), H(m)) == Speck(m, 0)`

Thus we can precompute `InvSpeck(len(m), H(m))` for a fixed length `m` (e.g., `len(m) == 9`), then bruteforce `m`.

We implemented this in [brute.cpp](brute.cpp). Some remarks about the implementation:

 * We optimized `Speck` to compute key expansion simultaneously to encrypting.
 * We bruteforce from a random starting point, computed using `arc4random()`.
 * We parallelize using OpenMP.
 * If we don't succeed before the alarm, we give up.

Since we were lazy to implement everything in C++, there is the small Python wrapper [solve.py](solve.py), which talks to the server and calls `brute` repeatedly, until it succeeds.

## Results

After running for about 30 minutes in 380 CPU cores, we got a solution:

```
bruteforcing b'7af4825f30f2'
[+] Starting local process './brute': pid 48572
[*] Process './brute' stopped with exit code 0 (pid 48572)
H(b'd88b2937f5f399b0f9') = b'7af4825f30f2'
[+] Receiving all data: Done (63B)
[*] Closed connection to 78.47.89.248 port 1952
b'The flag is: hxp{7h3Y_f1n4Lly_m4d3_a_t0Y_c1ph3R_f0r_CTF_Ta5kz}\n'
```

## Meet in the middle

Later we realized it would have been better to try messages consisting of two blocks (18 bytes), for which the hash computations can be simplified as follows:

`H(m) == Speck(len(m), Speck(m[9:], Speck(m[:9], 0)))`

Applying the decryption function two times, we get:

`InvSpeck(m[9:], InvSpeck(len(m), H(m))) == Speck(m[:9], 0)`

We can thus precompute several values of the left hand side, each for a different value of `m[9:]`, i.e., a meet in the middle attack.

If we precompute the left hand side for `n` different values of `m[9:]` and store the results in a map, each trial at a value for `m[:9]` will effectively evaluate `n` hashes, for a computational cost of at most `O(log n)`.

This technique is implemented in [meet.cpp](meet.cpp). It is able to complete in only 10 seconds when running in a dual core laptop.
