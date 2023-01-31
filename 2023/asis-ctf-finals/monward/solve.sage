from Crypto.Util.number import *

P = (2021000018575600424643989294466413996315226194251212294606, 1252223168782323840703798006644565470165108973306594946199)
Q = (2022000008169923562059731170137238192288468444410384190235, 1132012353436889700891301544422979366627128596617741786134)
R = (2023000000389145225443427604298467227780725746649575053047, 4350519698064997829892841104596372491728241673444201615238)
enc = (3419907700515348009508526838135474618109130353320263810121, 5140401839412791595208783401208636786133882515387627726929)

PP.<a, d> = PolynomialRing(ZZ)

polys = []
x, y = P
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = Q
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = R
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
x, y = enc
polys.append((a*x**2 + y**2 - d*x**2*y**2) - 1)
I = PP.ideal(polys)
G = I.groebner_basis()

p = factor(G[-1])[-1][0]
a = -(G[0].coefficients()[-1])%p
d = -(G[1].coefficients()[-1])%p

C = a, d, p

# https://crypto.stackexchange.com/questions/27842/edwards-montgomery-ecc-with-weierstrass-implementation
def Curve_EdwardsToMontgomery(p, a, d):
        A = (2*(a+d)*inverse(a-d, p))%p
        B = (4*inverse(a-d, p))%p
        return A, B

def Curve_EdwardsToWeierstrass(p, a, d):
        A, B = Curve_EdwardsToMontgomery(p, a, d)
        a = (1*inverse(B*B, p) - (A*A)*inverse(3*B*B,p))%p
        b = (A*(2*A**2 - 9)*inverse(27*B**3, p))%p
        return a, b


def Point_EdwardsToWeierstrass(p, a, d, P):
        x, y = P
        A, B = Curve_EdwardsToMontgomery(p, a, d)

        Px = ((1+y)*inverse(1-y, p))%p
        Py = ((1+y)*inverse(x-x*y, p))%p

        Pxx = ((Px + A*inverse(3, p))*inverse(B, p))%p
        Pyy = (Py*inverse(B, p))%p
        return E((Pxx, Pyy))

Wa, Wb = Curve_EdwardsToWeierstrass(p, a, d)

E = EllipticCurve(GF(p), [Wa, Wb])

P = Point_EdwardsToWeierstrass(p, a, d, P)
enc = Point_EdwardsToWeierstrass(p, a, d, enc)

print(long_to_bytes(int(discrete_log(enc,P,P.order(),operation='+'))))