from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from bitstring import BitArray, Bits
from pwn import *
import binascii
import base64
import string
import sys

ALL_ZEROS = b'\x00'*16
GCM_BITS_PER_BLOCK = 128

def pad(a):
    if len(a) < GCM_BITS_PER_BLOCK:
        diff = GCM_BITS_PER_BLOCK - len(a)
        zeros = ['0'] * diff
        a = a + zeros
    return a

def bytes_to_element(val, field, a):
    bits = BitArray(val)
    result = field.fetch_int(0)
    for i in range(len(bits)):
        if bits[i]:
            result += a^i
    return result

def multi_collide_gcm(keyset, nonce, tag, first_block=None, use_magma=False):
    # initialize matrix and vector spaces
    P.<x> = PolynomialRing(GF(2))
    p = x^128 + x^7 + x^2 + x + 1
    GFghash.<a> = GF(2^128,'x',modulus=p)
    if use_magma:
        t = "p:=IrreducibleLowTermGF2Polynomial(128); GFghash<a> := ext<GF(2) | p>;"
        magma.eval(t)
    else:
        R = PolynomialRing(GFghash, 'x')

    # encode length as lens
    if first_block is not None:
        ctbitlen = (len(keyset) + 1) * GCM_BITS_PER_BLOCK
    else:
        ctbitlen = len(keyset) * GCM_BITS_PER_BLOCK
    adbitlen = 0
    lens = (adbitlen << 64) | ctbitlen
    lens_byte = int(lens).to_bytes(16,byteorder='big')
    lens_bf = bytes_to_element(lens_byte, GFghash, a)

    # increment nonce
    nonce_plus = int((int.from_bytes(nonce,'big') << 32) | 1).to_bytes(16,'big')

    # encode fixed ciphertext block and tag
    if first_block is not None:
        block_bf = bytes_to_element(first_block, GFghash, a)
    tag_bf = bytes_to_element(tag, GFghash, a)
    keyset_len = len(keyset)

    if use_magma:
        I = []
        V = []
    else:
        pairs = []

    for k in keyset:
        # compute H
        aes = AES.new(k, AES.MODE_ECB)
        H = aes.encrypt(ALL_ZEROS)
        h_bf = bytes_to_element(H, GFghash, a)

        # compute P
        P = aes.encrypt(nonce_plus)
        p_bf = bytes_to_element(P, GFghash, a)

        if first_block is not None:
            # assign (lens * H) + P + T + (C1 * H^{k+2}) to b
            b = (lens_bf * h_bf) + p_bf + tag_bf + (block_bf * h_bf^(keyset_len+2))
        else:
            # assign (lens * H) + P + T to b
            b = (lens_bf * h_bf) + p_bf + tag_bf

        # get pair (H, b*(H^-2))
        y =  b * h_bf^-2
        if use_magma:
            I.append(h_bf)
            V.append(y)
        else:
            pairs.append((h_bf, y))

    # compute Lagrange interpolation
    if use_magma:
        f = magma("Interpolation(%s,%s)" % (I,V)).sage()
    else:
        f = R.lagrange_polynomial(pairs)
    coeffs = f.list()
    coeffs.reverse()

    # get ciphertext
    if first_block is not None:
        ct = list(map(str, block_bf.polynomial().list()))
        ct_pad = pad(ct)
        ct = Bits(bin=''.join(ct_pad))
    else:
        ct = ''
    
    for i in range(len(coeffs)):
        ct_i = list(map(str, coeffs[i].polynomial().list()))
        ct_pad = pad(ct_i)
        ct_i = Bits(bin=''.join(ct_pad))
        ct += ct_i
    ct = ct.bytes
    
    return ct+tag

first_block = b'\x01'
nonce = b'\x00'*12
tag = b'\x01'*16

# rr = process(['python', 'server.py'])
rr = remote('pythia.2021.ctfcompetition.com', 1337)
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

dic = {}
cts = []
block_size = 512
pos = []

def search():
    for k in range(len(cts)):
        if ok(cts[k][2]):
            l = cts[k][0]
            r = cts[k][1]
            print("Found password at [", l,",", r,"]")
            break
    while r-l > 1:
        mid = (l+r)//2
        keyset1 = pos[l:mid]
        ct1 = multi_collide_gcm(keyset1, nonce, tag, first_block=first_block)
        if ok(ct1):
            r = mid
        else:
            l = mid
    return dic[pos[l]]

def change_pass(to):
    rr.recvuntil(b">>> ")
    rr.sendline(b"1")
    rr.recvuntil(b">>> ")
    rr.sendline(str(to).encode())

def load_cts():
    fl = open("cts", "r")
    lines = fl.readlines()
    fl.close()
    for line in lines:
        lr = line.split(" ")
        l = int(lr[0])
        r = int(lr[1])
        ct = bytes.fromhex(lr[2][:-1])
        cts.append((l, r, ct))
    print("Loaded ciphertexts from file")

def generate_cts():
    fl = open("cts", "w")
    for i in range(len(pos)//block_size):
        l = i*block_size
        r = (i+1)*block_size
        ct = multi_collide_gcm(pos[l:r], nonce, tag)
        fl.write(str(l) + " " + str(r) + " " + ct.hex() + "\n")
    fl.close()
    print("Generated ciphertexts")

def generate_passwords():
    for i in string.ascii_lowercase:
        for j in string.ascii_lowercase:
            for k in string.ascii_lowercase:
                kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
                passw = (i+j+k).encode()
                key = kdf.derive(passw)
                dic[key] = passw
                pos.append(key)
    print("Generated passwords")

if __name__ == '__main__':
    generate_passwords()

    # generate_cts()
    load_cts()
    passw1 = search()
    print("First", passw1)

    change_pass(1)
    passw2 = search()
    print("Second", passw2)

    change_pass(2)
    passw3 = search()
    print("Third", passw3)

    # Retrieve flag
    rr.recvuntil(b">>> ")
    rr.sendline(b"2")
    rr.recvuntil(b">>> ")
    rr.sendline(passw1+passw2+passw3)
    rr.recvline()
    print(rr.recvline())
    rr.close()