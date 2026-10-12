import re
import json
import base64
import hashlib
from cryptography.fernet import Fernet

documents = {
    1: "Python is a popular programming language",
    2: "Java is used for enterprise application development",
    3: "Python supports machine learning and data science",
    4: "Artificial intelligence uses machine learning algorithms",
    5: "Data science involves statistics and visualization",
    6: "Cybersecurity protects networks and computer systems",
    7: "Encryption protects sensitive data and information",
    8: "Cloud computing provides scalable computing resources",
    9: "Computer networks enable communication between systems",
    10: "Python programming supports artificial intelligence"
}
print("DATASET")
for doc_id, text in documents.items():
    print(f"Document {doc_id}: {text}")
key = Fernet.generate_key()
cipher = Fernet(key)
def encrypt(data):
    """Encrypt a string using Fernet (AES-based encryption)."""
    if not isinstance(data, str):
        data = json.dumps(data, sort_keys=True)
    return cipher.encrypt(data.encode()).decode()
def decrypt(encrypted_data):
    """Decrypt ciphertext and return the original string."""
    return cipher.decrypt(encrypted_data.encode()).decode()
def tokenize(text):
    return re.findall(r"\b[a-zA-Z0-9]+\b", text.lower())
inverted_index = {}
for doc_id, text in documents.items():
    for word in set(tokenize(text)):
        inverted_index.setdefault(word, []).append(doc_id)
print("\nPLAIN INVERTED INDEX")
print(json.dumps(inverted_index, indent=2))
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = encrypt(word)
    encrypted_doc_ids = encrypt(json.dumps(doc_ids))
    encrypted_index[encrypted_word] = encrypted_doc_ids
print("\nENCRYPTED INVERTED INDEX")
print(json.dumps(encrypted_index, indent=2))
def search(query):
    print(f"\nSearch query: {query}")
    query_words = tokenize(query)
    if not query_words:
        print("Please enter a valid search query.")
        return
    encrypted_query = [encrypt(word) for word in query_words]
    print("\nEncrypted query terms:")
    for item in encrypted_query:
        print(item)
    matching_doc_ids = set()
    for encrypted_word, encrypted_ids in encrypted_index.items():
        stored_word = decrypt(encrypted_word)
        if stored_word in query_words:
            doc_ids = json.loads(decrypt(encrypted_ids))
            matching_doc_ids.update(doc_ids)
    if matching_doc_ids:
        print("\nMatching documents:")
        for doc_id in sorted(matching_doc_ids):
            print(f"Document {doc_id}: {documents[doc_id]}")
    else:
        print("No matching documents found.")
search("Python")
search("machine learning")
search("computer networks")
search("encryption data")