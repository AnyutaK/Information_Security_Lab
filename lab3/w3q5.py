import time
def power(a,b,p):
    if b==1:
        return a
    else:
        return pow(a,b) % p
def main():
    P=23
    print("The value of P:",P)
    G=5
    print("The value of G:",G)
    start_keygen=time.perf_counter()
    a=4
    print("The private key a for Alice:",a)
    x=power(G,a,P)
    print("the public key x for Alice:",x)
    b=3
    print("The private key b for Bob:",b)
    y=power(G,b,P)
    print("the public key y for Bob:",y)
    end_keygen = time.perf_counter()
    keygen_time = end_keygen - start_keygen
    print("Key generation time:", keygen_time, "seconds")
    start_exchange = time.perf_counter()
    ka=power(y,a,P)
    kb=power(x,b,P)
    end_exchange = time.perf_counter()
    exchange_time = end_exchange - start_exchange
    print("Key exchange time:", exchange_time, "seconds")
    print("Secret key for Alice is:",ka)
    print("Secret key for Bob is:",kb)
    if ka==kb:
        print("key exchange successful!")
    else:
        print("key exchange failed")

if __name__=="__main__":
    main()