#%%
def encrypt(plain_text,key):
    result = ""
    for char in plain_text:
        if char.isalpha():
            char=char.upper()
            encrypted_char= chr(((ord(char)- ord('A'))*key)%26+ord('A'))
            result += encrypted_char
        else:
            result += char
    return result

def decrypt(result,key):
    decrypted_result = ""
    key_inverse = pow(key,-1,26)
    for char in result:
        if char.isalpha():
            char=char.upper()
            decrypted_char=chr(((ord(char)- ord('A'))*key_inverse)%26+ord('A'))
            decrypted_result += decrypted_char
        else:
            decrypted_result += char
    return decrypted_result

while True:
    print("\nMultiplicative Cipher Function Menu")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")

    ch = input("Enter your choice (1-3): ")

    if ch == "1":
        plain_text= input ("enter the text")
        key = int(input("Enter the key: "))
        enc_msg= encrypt(plain_text,key);
        print("Encrypted message:", enc_msg)

    elif ch == "2":
        text = input("Enter the encrypted text: ")
        key = int(input("Enter the key: "))
        dec_msg= decrypt(text,key)
        print("Decrypted message:", dec_msg)
    elif ch == "3":
        print("Exiting program...")
        break

    else:
        print("Invalid choice! Please enter 1, 2, or 3.")
