from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import getpass
import sys
import os


def generar_llave(salt: bytes, password: str):
    password = password.encode("utf-8")
    KDF = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = KDF.derive(password)
    return key


def cifrar(path_entrada, path_salida, password):
    iv = os.urandom(12)
    salt = os.urandom(16)
    llave_aes = generar_llave(salt, password)
    datos_adicionales = iv + salt
    encryptor = Cipher(algorithms.AES(llave_aes), modes.GCM(iv), backend=default_backend()).encryptor()
    # Comprobación de data
    encryptor.authenticate_additional_data(datos_adicionales)
    # Abrir archivo binario
    salida_archivo = open(path_salida, "wb")

    for buffer in open(path_entrada, "rb"):
        data = encryptor.update(buffer)
        salida_archivo.write(data)

    encryptor.finalize()
    tag = encryptor.tag
    salida_archivo.write(iv+salt+tag)  # * 12,16,16 bytes
    salida_archivo.close()


def descifrar(path_entrada, path_salida, password):
    with open(path_entrada, "rb") as data:
        datos = data.read()

        datos_adicionales = datos[-44:]
        iv = datos_adicionales[:12]
        salt = datos_adicionales[12:28]
        tag = datos_adicionales[28:]
        llave_aes = generar_llave(salt, password)

    datos_adicionales = iv + salt

    decryptor = Cipher(algorithms.AES(llave_aes), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(datos_adicionales)

    salida_archivo = open(path_salida, "wb")
    for data in open(path_entrada, "rb"):
        datos_descifrados = decryptor.update(data)
        salida_archivo.write(datos_descifrados)
    salida_archivo.close()
    try:
        decryptor.finalize_with_tag
        print('Pasó la verificación de tag, todo OK')
    except:
        print('No pasó la verificación de tag, integridad comprometida')


if __name__ == '__main__':
    '''
    python3 aes_gcm.py cifrar path_entrada path_salida

    python3 aes_gcm.py descifrar path_entrada path_salida
    '''
    operacion = sys.argv[1]
    path_entrada = sys.argv[2]
    path_salida = sys.argv[3]
    #Password
    password = getpass.getpass(prompt='Password$: ')

    if operacion == "cifrar":
        cifrar(path_entrada, path_salida, password)
    elif operacion == 'descifrar':
        descifrar(path_entrada, path_salida, password)
    else:
        raise RuntimeError("No se ha podido completar la operación.")
        