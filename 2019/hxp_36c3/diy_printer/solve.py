# -*- coding: utf-8 -*-

from z3 import *

password = [ BitVec('pass_%d' % i, 8) for i in range(16) ]

s = Solver()

for c in password:
    s.add(c >= 0x20)
    s.add(c < 0x7f)

program = "P003I013WI015O1O1RTO2TO2QBO2DE1E1I013O1P000BO1TO1P002LBO1TDE1E1E1I008P003LI004P005LO1P000BO1TO1P002LBO1TDE1E1E1I005O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I010TI013O1O1NTP000BO2O2TQDO2TO2NDE1E1I002I005O1O1TNO2TO2NDO2O2NP002LDE1E1O1P000BO1TO1P002LBO1TDE1E1E1I009O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I005P019I012VI003VO1O1TNO2TO2NDO2O2NP002LDE1E1I000O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P004I004VI014I004O1O1TNO2TO2NDO2O2NP002LDE1E1O1P000BO1TO1P002LBO1TDE1E1E1I012O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P003I001WI004I003O1O1RTO2TBO2DE1E1O1P000BO1TO1P002LBO1TDE1E1E1I014O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P014I005I007O1O1RTO2TBO2DE1E1O1O1RTO2TBO2DE1E1I013O1O1RTO2TBO2DE1E1I011O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P001I006O1O1NTP000BO2O2TQDO2TO2NDE1E1I001O1O1TNO2TO2NDO2O2NP002LDE1E1P001I007O1O1NTP000BO2O2TQDO2TO2NDE1E1I002WO1O1RTO2TO2QBO2DE1E1I007O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P011P001I013I014O1O1RTO2TBO2DE1E1HO1O1RTO2TBO2DE1E1I015O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I012I006O1P000BO1TO1P002LBO1TDE1E1E1I012O1O1RTO2TBO2DE1E1I006O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P002I001WP002I014WO1O1RTO2TBO2DE1E1P001HI001O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I004I001I003O1P000BO1TO1P002LBO1TDE1E1E1O1O1TNO2TO2NDO2O2NP002LDE1E1I008O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P001P001I009I000O1O1RTO2TBO2DE1E1WHI003O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P003I010I009O1P000BO1TO1P002LBO1TDE1E1E1HI004O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1P007I006O1O1NTP000BO2O2TQDO2TO2NDE1E1P001I010TO1O1RTO2TBO2DE1E1HI010O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1I012I004O1O1RTO2TBO2DE1E1I002O1P000BO1TO1P002LBO1TDE1E1E1O1O1RTO2TO2QBO2DE1E1"
instr_ptr = 0
stack = []

def P():
    global program, instr_ptr

    argument = int(program[instr_ptr+1:instr_ptr+4])
    instr_ptr += 4

    #print "P(%d) [adiciona argumento à pilha]" % argument

    stack.append(argument)

def I():
    global program, instr_ptr

    argument = int(program[instr_ptr+1:instr_ptr+4])
    instr_ptr += 4

    #print "I(%d) [obtém caractere da entrada]" % argument

    #ascii_code = ord(password[argument])
    ascii_code = password[argument]

    stack.append(ascii_code)

def D():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "D(%d, %d)" % (a, b)

    c = a ^ 0xff

    d = a ^ b
    e = 2 * (c | b)

    f = 2 * c

    stack.append((d + e - f) & 0xff)

def B():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "B(%d, %d) [sub]" % (a, b)

    b = (-b) & 0xff

    c = b ^ 0xff
    d = a & c
    e = a & b

    stack.append((b + d + e) & 0xff)

def L():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "L(%d, %d)" % (a, b)

    c = b ^ 0xff
    d = -2
    e = 0

    for i in range(a):
        f = ~e
        e = (-f - c + d) & 0xff

    stack.append(e)

def V():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "V(%d, %d)" % (a, b)

    stack.append(a / b)

"""
    c = 0

    d = -b
    e = d ^ 0xff

    while a >= b:
        x = d ^ a
        y = 2 * (a | e)
        z = 2 * e

        a = x + y - z
        c += 1

    stack.append(c)
"""

def R():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "R(%d, %d) [xor]" % (a, b)

    c = (a + b) & 0xff
    d = a & b
    e = b & a

    stack.append((c - d - e) & 0xff)

def Q():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "Q(%d, %d)" % (a, b)

    c = a ^ 0xff
    d = a ^ b
    e = c | b

    stack.append((d + e - c)  & 0xff)

def N():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "N(%d, %d)" % (a, b)

    c = b ^ 0xff
    d = (-(a ^ b)) & 0xff
    e = a & c

    stack.append(d + e + b)

def H():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "H(%d, %d) [shift left]" % (a, b)

    stack.append((a << b) & 0xff)

def W():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()
    b = stack.pop()

    #print "W(%d, %d) [shift right]" % (a, b)

    stack.append(a >> b)

def T():
    global program, instr_ptr

    instr_ptr += 1

    a = stack.pop()

    #print "T(%d) [inverte bits]" % (a)

    stack.append(a ^ 0xff)

def O():
    global program, instr_ptr

    argument = int(program[instr_ptr+1:instr_ptr+2])
    instr_ptr += 2

    #print "O(%d) [adiciona elemento a partir da direita]" % argument

    stack.append(stack[- 1 - argument])

def E():
    global program, instr_ptr

    argument = int(program[instr_ptr+1:instr_ptr+2])
    instr_ptr += 2

    #print "E(%d) [elimina elemento a partir da direita]" % argument

    length = len(stack)
    del stack[- 1 - argument]

while instr_ptr < len(program):
    #print instr_ptr
    #print stack
    eval(program[instr_ptr] + "()")

s.add(stack[0] == 0)

if s.check() == sat:
    m = s.model()
    print "".join([ chr(int("%r" % m.evaluate(c))) for c in password ])
#print instr_ptr
#print stack
