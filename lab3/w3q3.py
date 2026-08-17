import random
a=random.randint(2,10)
def gcd(a,b):
    if a<b:
        return gcd(b,a)
    elif a%b==0:
        return b
    else:
        return gcd(a,b%a)
def modinv(a,p):
    return power(a,p-2,p)
def power(a,b,c):
    result=1
    a=a%c
    while b>0:
        if b%2==1:
            result=(result*a)%c
        a=(a*a)%c
        b//=2
    return result
def gen_key(p,g):
    x=random.randint(2,p-2)
    h=power(g,x,p)
    return x,h
def encrypt(msg,p,g,h):
    en_msg=[]
    k=random.randint(2,p-2)
    c1=power(g,k,p)
    s=power(h,k,p)
    for character in msg:
        m=ord(character)
        c2=(m*s)%p
        en_msg.append(c2)
    return en_msg,c1
def decrypt(en_msg,c1,x,p):
    dec_msg=""
    s=power(c1,x,p)
    s_inv=modinv(s,p)
    for c2 in en_msg:
        m=(c2*s_inv)%p
        dec_msg+=chr(m)
    return dec_msg
def main():
    p = 100000000000000000039
    g = 2
    x,h=gen_key(p,g)
    print("public key(p,g,h):")
    print("p=",p)
    print("g=",g)
    print("h=",h)
    print("private key (x):",x)
    msg=input("enter message:")
    print("Original Message :", msg)
    ct,c1= encrypt(msg, p, g, h)
    print("Encrypted Message :", ct)
    print("c1=",c1)
    dect=decrypt(ct,c1,x,p)
    print("Decrypted Message :", dect)
if __name__ == '__main__':
    main()