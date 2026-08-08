def getKeyMatrix(key_str):
    parts = [int(x) for x in key_str.replace(',', ' ').split()]
    keyMatrix = [[parts[0], parts[1]], [parts[2], parts[3]]]
    return keyMatrix
def encrypt(message_pair, keyMatrix):
    c1 = (keyMatrix[0][0] * message_pair[0] + keyMatrix[0][1] * message_pair[1]) % 26
    c2 = (keyMatrix[1][0] * message_pair[0] + keyMatrix[1][1] * message_pair[1]) % 26
    return [c1, c2]
def HillCipher(message, key):
    keyMatrix = getKeyMatrix(key)
    clean_msg = "".join([ch.upper() for ch in message if ch.isalpha()])
    if len(clean_msg) % 2 != 0:
        clean_msg += 'X'
    CipherText = []
    for i in range(0, len(clean_msg), 2):
        p1 = ord(clean_msg[i]) - 65
        p2 = ord(clean_msg[i + 1]) - 65
        encrypted_pair = encrypt([p1, p2], keyMatrix)
        CipherText.append(chr(encrypted_pair[0] + 65))
        CipherText.append(chr(encrypted_pair[1] + 65))
    print("Ciphertext:", "".join(CipherText))

key = input("enter key : ")
string = input("enter plain text: ")
print("Key text:", key)
print("Plain text:", string)
HillCipher(string, key)