def hash_string(s):
    hash_value=5381
    for char in s:
        hash_value=((hash_value*33)+ord(char))& 0XFFFFFFFF
        hash_value^=(hash_value>>16)
    return hash_value&0xFFFFFFFF
string=input("enter string to be hashed")
print("input string is:",string)
hashed=hash_string(string)
print(hashed,"is the final hash of string")