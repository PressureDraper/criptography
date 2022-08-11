import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys

#Estas funciones son inseguras
def simple_rsa_encrypt(m, publickey):
    # public_numbers regresa una estructura de datos con 'e' y 'n'
    numbers = publickey.public_numbers()
    # el cifrado es (m ** e) % n
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    # private_numbers regresa una estructura de datos con 'd' y 'n'
    numbers = privatekey.private_numbers()
    # el descifrado es (c ** d) % n
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def publicBytesToKey(public_key_bytes):
    # Convertir la llave publica de bytes a objeto llave
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    return public_key

def privateBytesToKey(private_key_bytes):
    # Convertir la llave privada de bytes a objeto llave
    # Como no se cifraron los bytes no hace falta un password
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        backend=default_backend(),
        password=None
    )

    return private_key

# RSA opera con numeros enteros, no bytes
# es neceario convertir un archivo de bytes a un entero para procesarlo
def int_to_bytes(i):
    # asegurarse de que es un entero python
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


if __name__ == "__main__":

    llave = sys.argv[1] #La llave pública o privada generada por el anterior script
    archivo = sys.argv[2] #El archivo a cifrar no mayor a 16 bytes
    do = sys.argv[3] #

    file = open(archivo, "rb")
    texto = file.read()
    file.close()

    file2 = open(llave, "rb")
    key = file2.read()
    file2.close() 

    int_mensaje = bytes_to_int(texto)
    print(int_mensaje)

    #Determinar si la llave es publica o privada
    arr = key.decode('utf-8').split('-')
    if arr[5] == "BEGIN PUBLIC KEY":
        key = publicBytesToKey(key)
    elif arr[5] == "BEGIN RSA PRIVATE KEY":
        key = privateBytesToKey(key)

    #Determinar la operacion a realizar
    if do.lower() == "cifrar":
        cifrado = simple_rsa_encrypt(int_mensaje, key)
        print(cifrado)
        # file3 = open("encode_RSA.txt", "wb")
        # file3.write(cifrado.encode('utf-8'))
        # file3.close()
    elif do.lower() == "descifrar":
        decifrado = simple_rsa_decrypt(archivo, key)
        original = int_to_bytes(decifrado)
        print(original)