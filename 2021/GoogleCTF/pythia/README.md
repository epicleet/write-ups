# Writeup Pythia

## Description:

Solves: 65

`Yet another oracle, but the queries are costly and limited so be frugal with them.`

## About the challenge

We are given a service with the source `1server.py`, looking through the source we can see that there is a list called `passwords` and the contents are **3 keys**, each one with **3 characters**. There are also 4 options to interact with the service:

1. Change the current encryption key, we can send an integer with the position of the key we want to use on option 3.
2. Read flag, that read the input and compares to see if they are the 3 passwords concatenated. If so they respond us with the flag.
3. Decrypt a cyphertext with nonce, this means that we can try decrypting a ciphertext with the password we set on option 1. The encryption algorithm is AESGCM, with a KDF(Scrypt) to derive a key from the password chosen. It returns to us if the ciphertext was decrypted successfully or not.
4. Exit

Another important thing to mention is that we can make 150 queries with 10 second delay each, so a naive bruteforce on all passwords won't work.

At first I was like "There is no way we can solve this", then I started thinking about some AESGCM vulnerabilities but none was leading me to a solution. With some failures, I started searching for some kind of vulnerability on the GCM, I mean mathematical problems on the design but none was helping.

C4v0k just sent a [reddit post](https://www.reddit.com/r/crypto/comments/n17k3t/my_breakdown_on_partition_oracle_attacks/) on the teams discord server. This post pretty much explain to us a real case about the multicolision keys vulnerability. Also this post link us to a [paper](https://eprint.iacr.org/2020/1491.pdf) called "Partitioning Oracle Attacks" that looks really promising. When I've read the multicolision function on AESGCM I immediately had a search idea and typed on discord: "What if we just compute a ciphertext that is accepted on half of the key space and check on the oracle if it decrypts? If it decrypts then we know that the key is inside this half space, if not we know that it is on the other half space, this give us a log(26^3) approach to solve the problem!"

Luckily the author of the paper already had an implementation to the attack, available at [Julia Len's repository](https://github.com/julialen/key_multicollision/blob/main/collide_gcm.sage). With this script it was _almost_ easy to code the search algorithm to find each password.

By _almost_ easy I mean that we can't just do a binary search on the key space, because 26^3 would take us a long time to compute everything.

Then a pretty straightforward solution was to make windows of keys, I mean make a ciphertext with the first 512 keys, then another with the next 512 and so on. With this approach we can precompute all the ciphertexts and then just send them to the server and see if the key is inside this window.

This first thing we have to do is to generate all 26^3 passwords. This can be done by just bruteforcing all 3 characters and generating all possible passwords.

```python
for i in string.ascii_lowercase:
    for j in string.ascii_lowercase:
        for k in string.ascii_lowercase:
            kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
            passw = (i+j+k).encode()
            key = kdf.derive(passw)
            dic[key] = passw
            pos.append(key)
print("Generated passwords")
```

Then I started coding the ciphertext windows generation, with the following:

```python
def generate_cts():
    fl = open("cts", "w")
    for i in range(len(pos)//block_size):
        l = i*block_size
        r = (i+1)*block_size
        ct = multi_collide_gcm(pos[l:r], nonce, tag)
        fl.write(str(l) + " " + str(r) + " " + ct.hex() + "\n")
    fl.close()
    print("Generated ciphertexts")
```

So we save all ciphertexts to a text file (just to not compute it every time we run the script). Then we search the window that contains the password:

```python
def ok(ct):
    payload = base64.b64encode(nonce)+b","+base64.b64encode(ct)
    rr.recvuntil(b">>> ")
    rr.sendline(b"3")
    rr.recvuntil(b">>> ")
    rr.sendline(payload)
    rr.recvline()
    if b"ERROR" in rr.recvline():
        return False
    else:
        return True
    
for k in range(len(cts)):
    if ok(cts[k][2]):
        l = cts[k][0]
        r = cts[k][1]
        print("Found password at [", l,",", r,"]")
        break
```

And after finding the window, we can run our binary search with the following code:

```python
while r-l > 1:
    mid = (l+r)//2
    keyset1 = pos[l:mid]
    ct1 = multi_collide_gcm(keyset1, nonce, tag, first_block=first_block)
    if ok(ct1):
        r = mid
    else:
        l = mid
    key = dic[pos[l]]
```

With all this parts we can make a `2solve.sage` script that interacts with the server and recover all 3 passwords. Another curious thing that I didn't mentioned is that the KDF function uses always the same salt, so it will generate always the same key on encryption, then our attack is done and we can run the solution. Here is the solve script output:
```bash
Generated passwords
Loaded ciphertexts from file
Found password at [ 13312 , 13824 ]
First b'tte'
Found password at [ 7680 , 8192 ]
Second b'mcw'
Found password at [ 5120 , 5632 ]
Third b'hth'
b'ACCESS GRANTED: CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}\n'

real	14m56,182s
user	0m17,513s
sys	0m0,897s
```

Finally we got it!