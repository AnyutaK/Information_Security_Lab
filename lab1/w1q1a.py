#%%
def encrypt(string, keys):
    result = ""
    for char in string:
        if char.isupper():
            result+=chr((ord(char) + keys - 65) % 26 + 65)
        elif char.islower():
            result+=chr((ord(char) + keys - 97) % 26 + 97)
        else:
            result+=char
    return result

def decrypt(string,keys):
    return encrypt(string,-keys)

while True:
    print("\nAdditive Cipher Function Menu")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")

    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        text = input("Enter the text: ")
        keys = int(input("Enter the key: "))
        print("Encrypted message:", encrypt(text, keys))

    elif choice == "2":
        text = input("Enter the encrypted text: ")
        keys = int(input("Enter the key: "))
        print("Decrypted message:", decrypt(text, keys))

    elif choice == "3":
        print("Exiting program...")
        break

    else:
        print("Invalid choice! Please enter 1, 2, or 3.")