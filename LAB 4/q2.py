import os, json, random
from datetime import datetime, timedelta
from sympy import isprime

KEY_DIR = 'C:/Users/Dhruv'  # change path
EXPIRY = timedelta(days=365)
os.makedirs(KEY_DIR, exist_ok=True)

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if isprime(p): return p

def rabin_key_pair(bits=1024):
    p, q = gen_prime(bits//2), gen_prime(bits//2)
    return p*q, (p,q)

def encrypt(pub, m): return (m*m) % pub

def decrypt(priv, c):
    p,q = priv; n = p*q
    sp, sq = pow(c,(p+1)//4,p), pow(c,(q+1)//4,q)
    return [(sp*sq)%n, (sp*(q-sq))%n, ((p-sp)*sq)%n, ((p-sp)*(q-sq))%n]

class KeyManager:
    def __init__(s): s.keys = {}; s.load()
    def gen(s,id,bits=1024):
        pub,priv = rabin_key_pair(bits)
        s.keys[id] = {
            'pub': pub, 'priv': priv,
            'created': datetime.now().isoformat(),
            'expiry': (datetime.now()+EXPIRY).isoformat()
        }
        s.save(); s.log('GEN',id); return pub,priv
    def get(s,id):
        k=s.keys.get(id)
        if k and datetime.now()<datetime.fromisoformat(k['expiry']): return k['pub'],k['priv']
        raise ValueError("Not found/expired")
    def revoke(s,id): s.keys.pop(id,None); s.save(); s.log('REVOKE',id)
    def renew(s):
        for id,k in list(s.keys.items()):
            if datetime.now()>=datetime.fromisoformat(k['expiry']):
                s.gen(id); s.log('RENEW',id)
    def save(s): json.dump(s.keys,open(f"{KEY_DIR}/keys.json","w"),indent=2)
    def load(s):
        f=f"{KEY_DIR}/keys.json"
        if os.path.exists(f): s.keys=json.load(open(f))
    def log(s,act,id):
        with open(f"{KEY_DIR}/audit.log","a") as f: f.write(f"{datetime.now()} - {act}:{id}\n")

if __name__=="__main__":
    km=KeyManager(); fid="hospital_123"
    pub,priv=km.gen(fid)
    print("Pub:",pub,"\nPriv:",priv)
    m=12345; c=encrypt(pub,m); dec=decrypt(priv,c)
    print("Enc:",c,"\nDec candidates:",dec)
    print("Recovered:",m if m in dec else None)
    km.renew(); km.revoke(fid); print("Keys after revoke:",km.keys)