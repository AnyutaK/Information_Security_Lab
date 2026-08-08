#It is a simple addition cipher
#Known-Plaintext Attack

def find_key(ciphertext_sample, plaintext_sample):
    c_val = ord(ciphertext_sample.upper()[0]) - 65
    p_val = ord(plaintext_sample.upper()[0]) - 65
    key = (c_val - p_val) % 26
    return key
def decrypt_shift_cipher(ciphertext, key):
    plaintext = []
    for char in ciphertext:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            c_val = ord(char) - ascii_offset
            p_val = (c_val - key) % 26
            plaintext.append(chr(p_val + ascii_offset))
        else:
            plaintext.append(char)
    return "".join(plaintext)
pt = input("enter sample plain text: ")
ct = input("enter sample ciphertext text: ")
tc= input("enter ciphertext text: ")
print("Sample Plain text:", pt)
print("Sample Cipher text:", ct)
print("Tablet Cipher text:", tc)
key = find_key(ct, pt)
print(f"Calculated Shift Key: {key}")
tablet_plain = decrypt_shift_cipher(tc, key)
print(f"Tablet Plaintext: {tablet_plain}")