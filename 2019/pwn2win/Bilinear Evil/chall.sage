import hashlib

m = 113
F.<z> = GF(2^m, modulus=x^113 + x^9 + 1)
Fx.<t> = F.extension(x^4 + x + 1)

b = 1
E = EllipticCurve(F, [0, 0, 1, 1, b])
Ex = EllipticCurve(Fx, [0, 0, 1, 1, b])
h = 1
r = E.cardinality() // h;

# Read master key for SOK authenticated key agreement
flag = open("flag.txt").read().strip()
assert len(flag) <= 64
secret = flag[7:][:-1] # extract secret from CTF-BR{<secret>}
msk = Integer(int(secret.encode("hex"), 16))

# Generate keys for Alice
xa = F(Integer(int(hashlib.sha256("Alice").digest().encode('hex'),16) % 2^m).bits())
while E.is_x_coord(xa) == false:
	xa*=z;
Pa = h*E.lift_x(xa)
Sa = msk * Pa;

# Generate keys for Bob
xb = F(Integer(int(hashlib.sha256("Bob").digest().encode('hex'),16) % 2^m).bits())
while E.is_x_coord(xb) == false:
	xb*=z;
Pb = h*E.lift_x(xb)
Sb = msk * Pb;

def pairing(P,Q):
	Px = Ex((P.xy()[0]),(P.xy()[1]))
	(x,y) = ((Q.xy()[0]),(Q.xy()[1]))
	Qx = Ex(x+t^4+t^2,y+(t^2+t)*x+t)
	return Px.tate_pairing(Qx,r,4,2^m)
	
sk1 = pairing(Sa,Pb);
sk2 = pairing(Sb,Pa);

# Make sure that the two shared keys are equal and the protocol works
assert sk1 == sk2

out = open("data.txt","w")
for p in sk1.list():
	s = "".join(str(e) for e in p.polynomial().list()[::-1])
	out.write(hex(Integer(s,2))+"\n")
