#!/usr/bin/python3

import angr
import claripy
import archinfo

def solve(filename):
    p = angr.Project(filename)

    find = (0x400a22, )

    inp_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(0x40)]
    inp = claripy.Concat(*inp_chars)

    st = p.factory.blank_state(args=[filename], stdin=inp)
    sm = p.factory.simgr(st)

    print("[*] executing")

    sm.explore(find=find)

    if len(sm.found) > 0:
        print("[+] found it")
        found = sm.found[0]
        
        rsp = found.regs.rsp
        found.add_constraints(found.memory.load(rsp, 8, endness=archinfo.Endness.LE) == 0x400a56)

        exp = found.solver.eval(inp, cast_to=bytes)
        return exp
    else:
        print("[-] failed")
        return None
