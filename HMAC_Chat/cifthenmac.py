from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
mensaje = b'hola mundo'

#Cifrar con CTR
key = os.urandom(16)
iv = os.urandom(16)

aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
aesEncryptor = aesCipher.encryptor()
cipher = aesEncryptor.update(mensaje)
aesEncryptor.finalize()

print(cipher)

#Aplicar HMAC
b = 128 #tamaño de bloque de sha256
k = os.urandom(b)

h = hmac.HMAC(k, hashes.SHA256(), backend=default_backend())
h.update(cipher)
print(h.finalize().hex())

#Decifrar CTR
aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
aesDecryptor = aesCipher.decryptor()
mensaje = aesDecryptor.update(cipher)
aesDecryptor.finalize()

print(mensaje)