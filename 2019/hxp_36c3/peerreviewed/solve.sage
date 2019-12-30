from Crypto.Util.number import bytes_to_long, long_to_bytes
from itertools import izip_longest

R = RealField(prec=200)
block_size = 192

# from the challenge source code
def merge_message(blocks):
    # Merge blocks
    blocks = [Integer(round(block)).bits()[::-1] for block in blocks]
    blocks = [[0] * (block_size - len(block)) + block for block in blocks]
    bits = flatten(blocks)
    # Remove padding
    bits = bits[:-bits[::-1].index(1)-1]
    # Convert back
    return long_to_bytes(Integer(bits, base=2))

def extendR3(vec):
    return vector(R, [vec[0], vec[1], 0])

def angleUnitVector(a, b):
    d = abs(a) * abs(b)
    vx = a.dot_product(b)/d
    vy = (extendR3(a).cross_product(extendR3(b)))[2]/d
    return vector(R, [vx, vy])

def angle(vec):
    # counter-clockwise, like any sane physicist would write
    return arctan2(vec[1], vec[0])

def rotate2d(theta):
    # counter-clockwise, like any sane physicist would write
    return matrix(R, [[cos(theta), -sin(theta)], [sin(theta), cos(theta)]])

def solve_for_b(yA, yB, yC):
    e2 = angle(angleUnitVector(yA, yB))
    uvec_b = rotate2d(-e2) * yC
    uvec_b = uvec_b / abs(uvec_b)
    abs_b = abs(yC) * abs(yA) / abs(yB)
    return abs_b * uvec_b

def main():
    blocks = []

    yA = vector(R, [5.8537179772742871378006829317359804640034149162093776176771e75, 2.0260990893806965307943860314007373888732002921518840941414e76])
    yB = vector(R, [4.0652782673020986683538918237010543408982543019306057179496e95, -5.0285426513783822097670201376390415563936061484095492229894e94])
    yC = vector(R, [4.3083595977562861674637990303350994431503203162436044206961e76, -3.1928247205608247346546681530367209122491766171698701927922e76])
    blocks.extend(solve_for_b(yA, yB, yC))

    yA = vector(R, [3.9886651421460868244883042163468164077791762065632163641999e76, -1.2487387183806776412156661578750877275468860853692530589115e77])
    yB = vector(R, [2.5644531171906756537679808003501733255703504126650573479133e95, -1.6570541229598112699074962433815055733294177769576178678896e96])
    yC = vector(R, [4.5893614625576224795913782492661186902913334535507951850089e76, 6.8611881934867127810471276550294069221078140676008042683634e76])
    blocks.extend(solve_for_b(yA, yB, yC))

    yA = vector(R, [-6.5089227887140404010136240391818701730482514213358150433451e75, 5.5620733870042242270647223203879530885369669489378834804472e76])
    yB = vector(R, [1.0017374772520318947002755790705886607122203555146923369286e95, 1.2876407911288161811207561236370324382394428286338064237471e96])
    yC = vector(R, [1.1418280384822587553925695577555385627605037374102719431688e77, -1.9966984339634055590175475802847306340483261373340080568330e76])
    blocks.extend(solve_for_b(yA, yB, yC))

    print(merge_message(blocks))

if __name__ == '__main__':
    main()

