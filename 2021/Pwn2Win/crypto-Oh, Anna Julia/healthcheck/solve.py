#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import requests
import json
import os
import socket


logging.basicConfig(level=0)


from pwn import *
import string
import gmpy2
from math import ceil, sqrt

def do_some_work(p):
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
    return flag


def solve(chall_addr, chall_port):
    p = None
    try:
        p = remote(chall_addr, int(chall_port))
    except Exception as e:
        # Unreachable
        logging.error('cannot solve crypto-anna-julia error={}', e)
        return -1

    flag = do_some_work(p)

    if 'CTF-BR{' in flag:
        return 1 # It's fine
    else:
        return 0 # Can't solve


def send_result(gateway, chall_name, res):
    data = {"chall-id": chall_name, "metric": res}
    r = None
    try:
        r = requests.post(gateway, data=json.dumps(data))
    except Exception as e:
        logging.error('something went wrong with error={}'.format(e))
    if r is not None and r.status_code != 201:
        logging.error('bad response from gateway with status_code={}'.format(str(r.status_code)))
    logging.info('sent result={} for chall={} with status_code={}'.format(str(res), chall_name, str(r.status_code)))

def main():
    logging.info('loading host and port')
    chall_addr = os.environ.get('CHALL_HOST')
    chall_port = os.environ.get('CHALL_PORT')
    chall_name = os.environ.get('CHALL_NAME')
    gateway = os.environ.get('GATEWAY_ADDR')
    if chall_addr is None:
        logging.error('please set up env CHALL_HOST')
        exit(-1)
    if chall_port is None:
        logging.error('please set up env CHALL_PORT')
        exit(-1)
    if chall_name is None:
        logging.error('please set up env CHALL_NAME')
        exit(-1)
    
    logging.info('trying to solve chall')
    res = solve(chall_addr, chall_port)

    logging.info('sending result={} for chall={} to gateway'.format(str(res), str(chall_name)))
    send_result(gateway, chall_name, res)
    logging.info('Job finished')

main()
