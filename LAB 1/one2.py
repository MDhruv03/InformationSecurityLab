def clean(msg):
    msg=msg.replace(" ", "").upper()
    return msg
def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encrypt(msg,key,choice):
    a,b = key if isinstance(key,tuple) else (key,0)
    result =""
    for ch in msg:
        if ch.isalpha():
            val=ord(ch)-65
            if choice=="1" :
                val=(val+a)%26
            elif choice=="2" :
                val=(val*a)%26
            elif choice =="3" :
                val=(val*a+b)%26
            result+=chr(val+65)
        else :
            result+=ch
    return result

def decrypt(msg,key,choice):
    a, b = key if isinstance(key, tuple) else (key, 0)
    inv_a = mod_inverse(a)
    if choice == "2" or choice == "3":
        if inv_a is None:
            return None
    result = ""
    for ch in msg:
        if ch.isalpha():
            val = ord(ch) - 65
            if choice == "1":
                val = (val - a) % 26
            elif choice == "2":
                val = (val * inv_a) % 26
            elif choice == "3":
                val = (inv_a * (val - b)) % 26
            result += chr(val + 65)
        else:
            result += ch
    return result

def menu():
    message="I am learning information security"
    message=clean(message)
    k=0
    while True:
        choice = input("1. Additive cipher \n"
                       "2. Multiplicative cipher\n"
                       "3. Affine cipher\n"
                       "4. Exit")
        if choice =='1':
            k=20 #key=20 given
        elif choice=='2':
            k = 15  # key=15 given
        elif choice=='3':
            k=(15,20)
        elif choice=='4':
            break

        enc = encrypt(message,k,choice)
        dec = decrypt(enc,k,choice)

        print(f"Original: {message}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")


if __name__=="__main__" :
    menu()

