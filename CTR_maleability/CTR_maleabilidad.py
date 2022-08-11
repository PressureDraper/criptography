from encodings import utf_8
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys

def calcXOR(bin1, bin2):

    bytes1 = list(bin1)
    bytes2 = list(bin2)

    if len(bytes2) < len(bytes1):
        menor = len(bytes2)
        mayor = bytes1
    else:
        menor = len(bytes1)
        mayor = bytes2
    
    resb = []

    for i in range(menor):
        resb.append(bytes1[i] ^ bytes2[i])
    
    return bytes(resb) + bytes(mayor[menor:])

def encode(path_in,path_out, key, iv):
    aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    aesEncryptor = aesCipher.encryptor()

    file = open(path_in, "rb")
    content = file.readlines()
    file.close()

    file_out = open(path_out, "wb")

    x = b''
    for buffer in content:
        cipher = aesEncryptor.update(buffer)
        x += cipher
        file_out.write(cipher)
        
    aesEncryptor.finalize()
    file_out.close()

    return x

def decode(path_in,path_out, key, iv):
    aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    aesDecryptor = aesCipher.decryptor()

    file = open(path_in, "rb")
    content = file.readlines()
    file.close()

    file_out = open(path_out, "wb")

    z = b''
    for buffer in content:
        bs = aesDecryptor.update(buffer)
        z += bs
        file_out.write(bs)

    aesDecryptor.finalize()
    file_out.close()

    return z

def malear(cifrado, key, iv, keystream):
    # aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    # aesDecryptor = aesCipher.decryptor()

    bytes1 = list(cifrado)
    # print(bytes1)

    text = b'Evil LLC'
    textu = list(text)
    print(text)

    # bytes 44:52
    cont = 0
    i = 0

    for s in range(len(bytes1)):
        if s == 0:
            bytes1[s] = 69
        if s == 1:
            bytes1[s] = 118
    
    # bs = aesDecryptor.update(bytes(bytes1))

    # aesDecryptor.finalize()

    return bytes1
    

if __name__ == "__main__":
    
    key = os.urandom(16)
    iv = os.urandom(16)

    planoXML = open("atacante.xml", "r")
    texto = planoXML.read()
    planoXML.close()
    planoXMLbin = texto.encode('utf-8')
    
    path_in = sys.argv[1]
    path_out = sys.argv[2]
    path_out2 = sys.argv[3]

    cifrado = encode(path_in, path_out, key, iv)

    # print(list(cifrado))

    key_stream = calcXOR(planoXMLbin, cifrado) #resultado de XOR a b'atacante.xml' y cifrado CTR atacante.xml con key e iv

    ans = malear(cifrado, key, iv, key_stream)
    print("VERGA")
    print(bytes(ans))

    cifrado2 = encode(, path_out2, key_stream, iv)

    c = calcXOR(key_stream, bytes(ans))
    print("JAJAJAJ")
    print(c)

    # b = decode(path_out, path_out2, key, iv)
    # print(b)