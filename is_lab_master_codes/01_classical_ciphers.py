"""Lab 1: classical substitution and transposition ciphers (educational only)."""

from math import gcd


def clean(text):
    return "".join(ch.upper() for ch in text if ch.isalpha())


def mod_inverse(a, m=26):
    return pow(a, -1, m)


def additive_encrypt(text, key):
    return "".join(chr((ord(c) - 65 + key) % 26 + 65) for c in clean(text))


def additive_decrypt(ciphertext, key):
    return additive_encrypt(ciphertext, -key)


def multiplicative_encrypt(text, key):
    if gcd(key, 26) != 1:
        raise ValueError("Multiplicative key must be coprime with 26")
    return "".join(chr(((ord(c) - 65) * key) % 26 + 65) for c in clean(text))


def multiplicative_decrypt(ciphertext, key):
    return multiplicative_encrypt(ciphertext, mod_inverse(key))


def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")
    return "".join(chr((a * (ord(c) - 65) + b) % 26 + 65) for c in clean(text))


def affine_decrypt(ciphertext, a, b):
    inv = mod_inverse(a)
    return "".join(chr((inv * ((ord(c) - 65) - b)) % 26 + 65) for c in clean(ciphertext))


def vigenere_encrypt(text, keyword):
    text, key = clean(text), clean(keyword)
    if not key:
        raise ValueError("Keyword cannot be empty")
    return "".join(chr((ord(c) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65)
                   for i, c in enumerate(text))


def vigenere_decrypt(ciphertext, keyword):
    text, key = clean(ciphertext), clean(keyword)
    return "".join(chr((ord(c) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65)
                   for i, c in enumerate(text))


def autokey_encrypt(text, initial_key):
    text = clean(text)
    stream = [initial_key % 26] + [ord(c) - 65 for c in text[:-1]]
    return "".join(chr((ord(c) - 65 + stream[i]) % 26 + 65) for i, c in enumerate(text))


def autokey_decrypt(ciphertext, initial_key):
    out, stream = [], [initial_key % 26]
    for i, c in enumerate(clean(ciphertext)):
        value = (ord(c) - 65 - stream[i]) % 26
        out.append(chr(value + 65))
        stream.append(value)
    return "".join(out)


def playfair_square(keyword):
    letters = []
    for c in clean(keyword).replace("J", "I") + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in letters:
            letters.append(c)
    return [letters[i:i + 5] for i in range(0, 25, 5)]


def playfair_pairs(text, decrypt=False):
    s = clean(text).replace("J", "I")
    if decrypt:
        return [s[i:i + 2] for i in range(0, len(s), 2)]
    pairs, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "X"
        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def playfair_transform(text, keyword, decrypt=False):
    square = playfair_square(keyword)
    pos = {square[r][c]: (r, c) for r in range(5) for c in range(5)}
    shift = -1 if decrypt else 1
    result = []
    for pair in playfair_pairs(text, decrypt):
        if len(pair) < 2:
            pair += "X"
        a, b = pair
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result += [square[ra][(ca + shift) % 5], square[rb][(cb + shift) % 5]]
        elif ca == cb:
            result += [square[(ra + shift) % 5][ca], square[(rb + shift) % 5][cb]]
        else:
            result += [square[ra][cb], square[rb][ca]]
    return "".join(result)


def hill_encrypt(text, key=((3, 3), (2, 7))):
    s = clean(text)
    if len(s) % 2:
        s += "X"
    out = []
    for i in range(0, len(s), 2):
        x, y = ord(s[i]) - 65, ord(s[i + 1]) - 65
        out += [chr((key[0][0] * x + key[0][1] * y) % 26 + 65),
                chr((key[1][0] * x + key[1][1] * y) % 26 + 65)]
    return "".join(out)


def hill_decrypt(ciphertext, key=((3, 3), (2, 7))):
    a, b = key[0]
    c, d = key[1]
    det_inv = mod_inverse((a * d - b * c) % 26)
    inverse = ((d * det_inv % 26, -b * det_inv % 26),
               (-c * det_inv % 26, a * det_inv % 26))
    return hill_encrypt(ciphertext, inverse)


def rail_fence_encrypt(text, rails):
    if rails < 2:
        return text
    rows, row, direction = [""] * rails, 0, 1
    for ch in text:
        rows[row] += ch
        if row in (0, rails - 1):
            direction *= -1
        row -= direction
    return "".join(rows)


def rail_fence_decrypt(ciphertext, rails):
    if rails < 2:
        return ciphertext
    pattern, row, direction = [], 0, 1
    for _ in ciphertext:
        pattern.append(row)
        if row in (0, rails - 1):
            direction *= -1
        row -= direction
    counts = [pattern.count(r) for r in range(rails)]
    rows, start = [], 0
    for count in counts:
        rows.append(list(ciphertext[start:start + count])); start += count
    return "".join(rows[r].pop(0) for r in pattern)


def columnar_encrypt(text, keyword):
    text, keyword = clean(text), clean(keyword)
    cols = len(keyword)
    text += "X" * ((-len(text)) % cols)
    order = sorted(range(cols), key=lambda i: (keyword[i], i))
    return "".join(text[i::cols] for i in order)


def columnar_decrypt(ciphertext, keyword):
    keyword, ciphertext = clean(keyword), clean(ciphertext)
    cols, rows = len(keyword), len(ciphertext) // len(keyword)
    order = sorted(range(cols), key=lambda i: (keyword[i], i))
    columns, start = {}, 0
    for col in order:
        columns[col] = ciphertext[start:start + rows]; start += rows
    return "".join(columns[c][r] for r in range(rows) for c in range(cols))


def additive_bruteforce(ciphertext):
    return {key: additive_decrypt(ciphertext, key) for key in range(26)}


def demo():
    text = input("Plaintext: ")
    print("1 Additive  2 Multiplicative  3 Affine  4 Vigenere  5 Autokey")
    print("6 Playfair  7 Hill  8 Rail fence  9 Columnar")
    choice = input("Choice: ")
    if choice == "1":
        key = int(input("Key: ")); c = additive_encrypt(text, key); p = additive_decrypt(c, key)
    elif choice == "2":
        key = int(input("Coprime key: ")); c = multiplicative_encrypt(text, key); p = multiplicative_decrypt(c, key)
    elif choice == "3":
        a, b = map(int, input("a b: ").split()); c = affine_encrypt(text, a, b); p = affine_decrypt(c, a, b)
    elif choice == "4":
        key = input("Keyword: "); c = vigenere_encrypt(text, key); p = vigenere_decrypt(c, key)
    elif choice == "5":
        key = int(input("Initial key: ")); c = autokey_encrypt(text, key); p = autokey_decrypt(c, key)
    elif choice == "6":
        key = input("Keyword: "); c = playfair_transform(text, key); p = playfair_transform(c, key, True)
    elif choice == "7":
        c = hill_encrypt(text); p = hill_decrypt(c)
    elif choice == "8":
        key = int(input("Rails: ")); c = rail_fence_encrypt(text, key); p = rail_fence_decrypt(c, key)
    elif choice == "9":
        key = input("Keyword: "); c = columnar_encrypt(text, key); p = columnar_decrypt(c, key)
    else:
        return print("Invalid choice")
    print("Encrypted:", c)
    print("Decrypted:", p)


if __name__ == "__main__":
    demo()
