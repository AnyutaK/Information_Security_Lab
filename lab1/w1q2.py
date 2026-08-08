
def gen_key(msg,key):
    key=list(key)
    if len(key)== len(msg):
        return key
    else:
        for i in range(len(msg)-len(key)):
            key.append(key[i%len(key)])
        return "".join(key)
def encrypt_vigenere(msg,key):
    encrypted_msg=""
    key=gen_key(msg,key)
    for i in range(len(msg)):
        char=msg[i]
        encrypted_char=""
        if char.isupper():
            encrypted_char+=chr((ord(char)+ ord(key[i]) -2 * ord ('A'))% 26 + ord ('A'))
        elif char.islower():
            encrypted_char+=chr((ord(char)+ ord(key[i]) -2 * ord ('a'))% 26 + ord ('a'))
        else:
            encrypted_char+=char
        encrypted_msg+=encrypted_char
    return encrypted_msg
def decrypt_vigenere(msg,key):
    decrypted_msg=""
    key=gen_key(msg,key)
    for i in range(len(msg)):
        char=msg[i]
        decrypted_char=""
        if char.isupper():
            decrypted_char= chr((ord(char) - ord(key[i]) +26)% 26 + ord ('A'))
        elif char.islower():
            decrypted_char= chr((ord(char) - ord(key[i]) +26)% 26 + ord ('a'))
        else:
            decrypted_char= char
        decrypted_msg+=decrypted_char
    return decrypted_msg

def encrypt_autokey(msg,key):
    msg=msg.upper().replace(" ","")
    key_stream=[key]
    for i in range(len(msg) -1):
        key_stream.append(ord(msg[i]) - ord('A'))
    cipher=""
    for i in range(len(msg)):
        p= ord(msg[i]) - ord('A')
        c=(p +key_stream[i])%26
        cipher+=chr(c+ord ('A'))
    return cipher
def decrypt_autokey(cipher,key):
    plain=""
    current_key=key
    for ch in cipher:
        c=ord(ch) - ord('A')
        p=(c-current_key+26)%26
        plain+=chr(p+ord ('A'))
        current_key=p
    return plain
while True:
    print("\nCIPHER MENU\n")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Exit")
    choice = input("Enter your choice: ")
    if choice == "1":
        text = input("Enter plaintext: ")
        key = input("Enter key: ")
        cipher = encrypt_vigenere(text, key)
        print("Encrypted:", cipher)
        plain = decrypt_vigenere(cipher, key)
        print("Decrypted:", plain)
    elif choice == "2":
        text = input("Enter plaintext: ")
        key = int(input("Enter key: "))
        cipher = encrypt_autokey(text, key)
        print("Encrypted:", cipher)
        plain = decrypt_autokey(cipher, key)
        print("Decrypted:", plain)
    elif choice == "3":
        print("Exiting...")
        break
    else:
        print("Invalid choice!")


