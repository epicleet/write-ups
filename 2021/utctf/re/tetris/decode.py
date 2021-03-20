#!/usr/bin/python3

from sys import argv
from struct import unpack

u8 = lambda x : unpack("<B", x)[0]
u32 = lambda x : unpack("<I", x)[0]

PAGE_START = 0xf0
PAGE_END = 0xf1

filename = argv[1]

fin = open(filename, 'rb')
data = fin.read()

header = data[:8]
print(f'header: {header}')

idx = 8
siz = len(data)

inside = False

def get_(d, idx, siz):
    return d[idx:idx+siz]

pages = []
page = None
p_idx = 0

while idx < siz:
    if inside:
        if u8(get_(data, idx, 1)) == PAGE_END:
            print(f'{idx}: END')
            inside = False

            pages.append(page)
            print(page)
        else:
            typ = u8(get_(data, idx, 1))
            run = u32(get_(data, idx+1, 4))
            print(f'{idx}: type = {typ}, run = {run}')
            idx += 4
            
            p_idx += run
            if p_idx < 240:
                page.append((p_idx, typ))
    else:
        if u8(get_(data, idx, 1)) == PAGE_START:
            print(f'{idx}: START')
            inside = True

            p_idx = 0
            page = []
    idx += 1

def reset_page():
    return [ [ '.' ] * 10 for _ in range(24) ]

def print_page(p):
    c_typ = 9
    for r in range(24):
        for c in range(10):
            if p[r][c] != '.' and p[r][c] != c_typ:
                c_typ = p[r][c]
            p[r][c] = str(c_typ)
            
    for i in range(24):
        print('|' + ''.join(map(str, p[23-i])) + '|')

for idx, page in enumerate(pages):
    print(f'Page #{idx+1}:')
    print(page)
    p = reset_page()

    for coord, typ in page:
        c = coord%10
        r = coord//10
        p[r][c] = typ

    print_page(p)
