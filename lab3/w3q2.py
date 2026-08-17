from ecies import encrypt,decrypt
from eth_keys import keys
from coincurve import utils
import binascii
privKey = keys.PrivateKey(utils.get_valid_secret())
PrivKeyHex=privKey.to_hex()
pubKeyHex=privKey.public_key.to_hex()
print("encryption public key:",pubKeyHex)
print("decryption private key:",PrivKeyHex)
pt=input("enter message for encryption:")
msg=pt.encode()
print("original message:",pt)
encrypted=encrypt(pubKeyHex,msg)
print("encrypted message:",binascii.hexlify(encrypted))
decrypted=decrypt(PrivKeyHex,encrypted)
print("decrypted message:",decrypted.decode())

#pip install eth-keys
#pip install eciespy