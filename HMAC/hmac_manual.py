#Implementación manual
import hashlib
import os

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

if __name__ == "__main__":
    b = 128 #tamaño de bloque de sha256
    entry = b'hi world!'

    ipad = bytes([54]) * b #hexadecimal 36 = ipad = b'36' -> int('36', 16) | decimal 54
    opad = bytes([92]) * b #hexadecimal 5c = ipad = b'5c' -> int('5c', 16) | decimal 92

    k = os.urandom(b)
    kipad = calcXOR(k, ipad)
    # print(kipad)

    hasher = hashlib.sha256()
    hasher.update(kipad + entry)
    innerHash = hasher.digest()
    # print(innerHash)

    kopad = calcXOR(k, opad)
    hasher = hashlib.sha256()
    hasher.update(kopad + innerHash)
    mac = hasher.hexdigest()
    print(mac)