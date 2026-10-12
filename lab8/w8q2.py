import re
import json
from phe import paillier

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
public_key, private_key = paillier.generate_paillier_keypair(
    n_length=2048
)
def encrypt_data(data):
    """Encrypt an integer using the public key."""
    return public_key.encrypt(int(data))
def decrypt_data(encrypted_data):
    """Decrypt an encrypted integer using the private key."""
    return private_key.decrypt(encrypted_data)
def tokenize(text):
    return re.findall(r"\b[a-zA-Z0-9]+\b", text.lower())
inverted_index = {}
for doc_id, text in documents.items():
    for word in set(tokenize(text)):
        inverted_index.setdefault(word, []).append(doc_id)
print("\nPLAIN INVERTED INDEX")
print(json.dumps(inverted_index, indent=2))
vocabulary = sorted(inverted_index.keys())
word_to_id = {
    word: i + 1 for i, word in enumerate(vocabulary)
}
id_to_word = {
    i + 1: word for i, word in enumerate(vocabulary)
}
encrypted_index = {}
for word, doc_ids in inverted_index.items():
    word_id = word_to_id[word]
    encrypted_word_id = encrypt_data(word_id)
    encrypted_doc_ids = [
        encrypt_data(doc_id) for doc_id in doc_ids
    ]
    encrypted_index[word] = {
        "encrypted_word_id": encrypted_word_id,
        "encrypted_doc_ids": encrypted_doc_ids
    }
print("\nENCRYPTED INDEX")
print("Index encrypted successfully.")
print("Number of indexed terms:", len(encrypted_index))
def search(query):
    print("\nSearch query:", query)
    query_words = set(tokenize(query))
    if not query_words:
        print("Please enter a valid query.")
        return
    encrypted_query = {
        word: encrypt_data(word_to_id[word])
        for word in query_words
        if word in word_to_id
    }
    print("\nQuery encrypted using Paillier public key.")
    matching_doc_ids = set()
    for word, query_ciphertext in encrypted_query.items():
        query_word_id = decrypt_data(query_ciphertext)

        for stored_word, entry in encrypted_index.items():
            stored_word_id = decrypt_data(
                entry["encrypted_word_id"]
            )
            if query_word_id == stored_word_id:
                for encrypted_doc_id in entry["encrypted_doc_ids"]:
                    doc_id = decrypt_data(encrypted_doc_id)
                    matching_doc_ids.add(doc_id)
    if matching_doc_ids:
        print("\nMatching document IDs:",
              sorted(matching_doc_ids))
        print("\nMATCHING DOCUMENTS")
        for doc_id in sorted(matching_doc_ids):
            print(f"Document {doc_id}: {documents[doc_id]}")
    else:
        print("No matching documents found.")
search("Python")
search("machine learning")
search("computer networks")
search("encryption data")
search("blockchain")