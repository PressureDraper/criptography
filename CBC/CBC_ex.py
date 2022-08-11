from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

key = base64.b64encode(b'5' * 16)

iv = base64.b64encode(os.urandom(10))

aesCipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend)
aesEncryptor = aesCipher.encryptor()

#Cifrar
data = "cadena random a cifrar"
padder = padding.PKCS7(128).padder()
rest = padder.update(data) #padder.update solo jala 16 bytes y lo demas se queda en buffer
print(rest)
rest += padder.finalize() #finalize agrega el padding necesario para complementar la cadena y el tamaño minimo de bloque
print(rest)
cipher = aesEncryptor.update(rest)
aesEncryptor.finalize()
print(cipher)

#Decifrar
aesDecryptor = aesCipher.decryptor()
unpadder = padding.PKCS7(128).unpadder()
plano = aesDecryptor.update(cipher) #Se decifra el contenido con el padding
print(plano)
aesDecryptor.finalize()
data = unpadder.update(plano)
print(data + unpadder.finalize())