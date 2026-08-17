def power(base,expo,m):
    res=1
    base=base%m
    while expo>0:
        if expo&1:
            res=(res*base)%m
        base=(base*base)%m
        expo=expo//2
    return res
def modInv(e,phi):
    for d in range(2,phi):
        if (e*d)%phi==1:
            return d
    return -1
def generateKeys():
    p=7919
    q=1009
    n=p*q
    phi=(p-1)*(q-1)
    e=0
    for e in range(2,phi):
        if gcd(e,phi)==1:
            break
    d=modInv(e,phi)
    return e,d,n
def gcd(a,b):
    while b!=0:
        a,b=b,a%b
    return a
def encrypt(message, e, n):
    return [pow(ord(ch), e, n) for ch in message]
def decrypt(ciphertext, d, n):
    return ''.join(chr(pow(c, d, n)) for c in ciphertext)
def main():
    e,d,n=generateKeys()
    print(f"Public Key (n,e):({n},{e})")
    print(f"Private Key (n,d):({n},{d})")
    message=input("Enter message:")
    print(f"Message: {message}")
    C=encrypt(message,e,n)
    print(f"Encrypted message: {C}")
    D=decrypt(C,d,n)
    print(f"Decrypted message: {D}")
if __name__ == "__main__":
    main()
