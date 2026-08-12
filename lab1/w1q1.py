#%%
def additive_encrypt(text,key):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + key - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + key - 97) % 26 + 97)
        else:
            result += char
    return result
def additive_decrypt(cipher,key):
     return additive_encrypt(cipher, -key)
def multiplicative_encrypt(text,key):
    result = ""
    for char in text:
        if char.isalpha():
            char = char.upper()
            encrypted_char = chr(((ord(char) - ord('A')) * key) % 26 + ord('A'))
            result += encrypted_char
        else:
            result += char
    return result
def multiplicative_decrypt(cipher,key):
    decrypted_result = ""
    key_inverse = pow(key, -1, 26)
    for char in cipher:
        if char.isalpha():
            char = char.upper()
            decrypted_char = chr(((ord(char) - ord('A')) * key_inverse) % 26 + ord('A'))
            decrypted_result += decrypted_char
        else:
            decrypted_result += char
    return decrypted_result
def affine_encrypt(text,k1,k2):
    result = ""
    for char in text:
        if char.isalpha():
            order = ord(char)
            if char.islower():
                order = order - 97
                order = ((order * k1) + k2) % 26
                order = order + 97
                new_char = chr(order)
                result += new_char
            elif char.isupper():
                order = order - 65
                order = ((order * k1) + k2) % 26
                order = order + 65
                new_char = chr(order)
                result += new_char
        else:
            result += char
    return result
def affine_decrypt(cipher,k1,k2):
    key_inverse = pow(k1, -1, 26)
    plaintexts = ""
    for char in cipher:
        if char.isalpha():
            order = ord(char)
            if char.islower():
                order = order - 97
                order = ((order - k2) * key_inverse) % 26
                order = order + 97
                new_char = chr(order)
                plaintexts += new_char
            elif char.isupper():
                order = order - 65
                order = ((order - k2) * key_inverse) % 26
                order = order + 65
                new_char = chr(order)
                plaintexts += new_char
        else:
            plaintexts += char
    return plaintexts, key_inverse

while True:
    print("\nCIPHER MENU\n")
    print("1. Additive Cipher")
    print("2. Multiplicative Cipher")
    print("3. Affine Cipher")
    print("4. Exit")
    choice = input("Enter your choice: ")
    if choice == "1":
        text = input("Enter plaintext: ")
        key = int(input("Enter key: "))
        cipher = additive_encrypt(text, key)
        print("Encrypted:", cipher)
        plain = additive_decrypt(cipher, key)
        print("Decrypted:", plain)
    elif choice == "2":
        text = input("Enter plaintext: ")
        key = int(input("Enter key: "))
        cipher = multiplicative_encrypt(text, key)
        print("Encrypted:", cipher)
        plain = multiplicative_decrypt(cipher, key)
        print("Decrypted:", plain)
    elif choice == "3":
        text = input("Enter plaintext: ")
        k1 = int(input("Enter Key1: "))
        k2 = int(input("Enter Key2: "))
        cipher = affine_encrypt(text, k1, k2)
        print("Encrypted:", cipher)
        plain, inv = affine_decrypt(cipher, k1, k2)
        print("Multiplicative Inverse:", inv)
        print("Decrypted:", plain)
    elif choice == "4":
        print("Exiting...")
        break
    else:
        print("Invalid choice!")