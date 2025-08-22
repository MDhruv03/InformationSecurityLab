from Crypto.Util.number import inverse, getRandomRange
import random

# Curve parameters for secp192r1 (prime p, a, b, base point G)
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = -3
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
G = (
    0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
    0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
)

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        m = (3 * x1 * x1 + a) * inverse(2 * y1, p) % p
    else:
        m = (y2 - y1) * inverse(x2 - x1, p) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = None
    while k > 0:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R

# Key gen: private d, public Q = d*G
d = random.randrange(1, p)
Q = scalar_mult(d, G)

# Message M as a scalar (for example)
M = 12345
M_point = scalar_mult(M, G)

# Encrypt
k = random.randrange(1, p)
C1 = scalar_mult(k, G)
C2 = point_add(M_point, scalar_mult(k, Q))

# Decrypt
S = scalar_mult(d, C1)
S_inv = (S[0], (-S[1]) % p)
decrypted_point = point_add(C2, S_inv)

# Recover M by brute force (small M)
for i in range(1, 20000):
    if scalar_mult(i, G) == decrypted_point:
        recovered = i
        break

print("Original M:", M)
print("Decrypted M:", recovered)
