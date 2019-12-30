#!/usr/bin/python3
from pwn import *
while True:
    server = remote('78.47.89.248', 1952)
    h = server.recvline().strip()
    print('bruteforcing %r' % h)
    bruter = process(['./brute', h], stdout=PIPE)
    if bruter.poll(block=True) == -signal.SIGALRM:
        print('timeout')
    else:
        s = bruter.recvline().strip()
        print('H(%r) = %r' % (s, h))
        server.sendline(s)
        print(server.recvall(2))
        sys.exit(0)
    bruter.close()
    server.close()
