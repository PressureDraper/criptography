from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

#cifrar
def encode(path_in,path_out, key, iv):
    aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    aesEncryptor = aesCipher.encryptor()

    file = open(path_in, "rb")
    content = file.readlines()
    file.close()

    file_out = open(path_out, "wb")

    for buffer in content:
        cipher = aesEncryptor.update(buffer)
        print(cipher)
        file_out.write(cipher)
        

    aesEncryptor.finalize()
    file_out.close()


#decifrar
def decode(path_in,path_out, key, iv):
    aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    aesDecryptor = aesCipher.decryptor()

    file = open(path_in, "rb")
    content = file.readlines()
    file.close()

    file_out = open(path_out, "wb")

    for buffer in content:
        bs = aesDecryptor.update(buffer)
        file_out.write(bs)

    aesDecryptor.finalize()
    file_out.close()



key = os.urandom(16)

iv = os.urandom(16)

path_in = r"C:\Users\warma\Desktop\8vo_Semestre\Criptografia\hwks\ctrin.txt"
path_out = r"C:\Users\warma\Desktop\8vo_Semestre\Criptografia\hwks\ctrout.txt"

encode(path_in, path_out, key, iv)

path_in = r"C:\Users\warma\Desktop\8vo_Semestre\Criptografia\hwks\ctrout.txt"
path_out = r"C:\Users\warma\Desktop\8vo_Semestre\Criptografia\hwks\ctrdecoded.txt"

decode(path_in, path_out, key, iv)
