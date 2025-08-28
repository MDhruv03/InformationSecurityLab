import string
charset = string.ascii_uppercase

pt, ct = "AB", "GL"
def get_params():
    for a in range(27):
        for b in range(27):
            results = [ (a * charset.index(p) + b) % 26 == charset.index(c) for p, c in zip(pt, ct)]
            if all(results):
                print(f"{a = }\n{b = }")
                return a, b

    return  None

a, b = get_params()
ciph = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a_inv = 1
while (a * a_inv) % 26 != 1:
    a_inv += 1
pt = ""
for i in ciph:
    pt += charset[(((charset.index(i) - b) % 26) * a_inv) % 26]

print(pt) # THEBESTOFAFIGHTISMAKINGUPAKTERWARDS