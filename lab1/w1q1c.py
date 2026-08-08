#%%
def encrypt(plaintext,Key1,Key2):
    result = ""
    for char in plaintext:
        if char.isalpha():
            order=ord(char)
            if char.islower():
                order=order -97
                order= ((order *Key1)+Key2) %26
                order =order + 97
                new_char = chr(order)
                result += new_char
            elif char.isupper():
                order =order -65
                order= ((order *Key1)+Key2) %26
                order =order + 65
                new_char = chr(order)
                result += new_char
        else:
            result += char
    return result

def decrypt(res,Key1,Key2):
    key_inverse = pow(Key1,-1,26)
    plaintexts = ""
    for char in res:
        if char.isalpha():
            order=ord(char)
            if char.islower():
                order= order-97
                order= ((order -Key2)*key_inverse) %26
                order = order + 97
                new_char = chr(order)
                plaintexts += new_char
            elif char.isupper():
                order =order -65
                order= ((order -Key2)*key_inverse) %26
                order =order + 65
                new_char = chr(order)
                plaintexts += new_char
        else:
            plaintexts += char
    return plaintexts,key_inverse

while True:
    print("\nAffine Cipher Function Menu")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")

    ch = input("Enter your choice (1-3): ")

    if ch == "1":
        Key1 = int(input("enter the first key"))
        print ("first key is",Key1)
        Key2 = int(input("enter the second key"))
        print ("second key is",Key2)
        plaintext= input ("enter the string")
        print( "the string is",plaintext)
        encr_msg= encrypt(plaintext,Key1,Key2)
        print("the encrypted message is :" ,encr_msg)

    elif ch == "2":
        text = input("Enter the encrypted text: ")
        Key1 = int(input("enter the first key"))
        print ("first key is",Key1)
        Key2 = int(input("enter the second key"))
        print ("second key is",Key2)
        print( "the encrypted string is",text)
        decr_msg,inv_key= decrypt(encr_msg,Key1,Key2)
        print("the decrypted message is :",decr_msg)

    elif ch == "3":
        print("Exiting program...")
        break

    else:
        print("Invalid choice! Please enter 1, 2, or 3.")
