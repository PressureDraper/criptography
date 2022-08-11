"""
mensajes.

Módulo utileria para manejo de mensajes de chat
"""
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from cryptography. hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography . hazmat . primitives . ciphers . aead import AESGCM
DELIMITADOR = b'###$###'


def quitar_delimitador(mensaje):
    """
    Limpia un mensaje para que no tenga delemitador.
    Keyword Arguments:
    mensaje --
    returns: bytes
    """
    if not mensaje.endswith(DELIMITADOR):
        return mensaje
    return mensaje[:-len(DELIMITADOR)]


def leer_mensaje(socket):
    """
    Permite leer un mensaje de longitud arbitraria, utilizando delimitadores de mensaje.

    Keyword Arguments:
    socket de cliente
    returns: bytes
    """
    chunk = socket.recv(1024)
    mensaje = b''
    while not chunk.endswith(DELIMITADOR):
        mensaje += chunk
        if DELIMITADOR in mensaje:
            break
        chunk = socket.recv(1024)
    mensaje += chunk
    return quitar_delimitador(mensaje)


def leer_archivo(socket, path_salida, aes):
    name_file = path_salida.split("/")[1]
    chunk = socket.recv(10240)
    salida = open('/tmp/{0}'.format(name_file), 'bw')

    #Datos para cifrar
    datos = chunk[:40]
    iv = datos[:12]
    tag = datos[24:40]
    chunk = chunk[40:]

    while not chunk.endswith(DELIMITADOR):
        salida.write(chunk)
        chunk = socket.recv(1024)
        
    final = quitar_delimitador(chunk)
    salida.write(final)
    salida.close()

    add = b'datos adicionales random para aes gcm'
    decryptor = Cipher(algorithms.AES(aes), modes.GCM(
        iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(add)
    salida_archivo = open(path_salida, "bw")

    for buffer in open('/tmp/{0}'.format(name_file), 'rb'):
        datos_descifrados = decryptor.update(buffer)
        salida_archivo.write(datos_descifrados)
    salida_archivo.close()
    try:
        decryptor.finalize_with_tag
        print('---TAG VÁLIDO---')
    except:
        print('No pasó la verificación de tag, integridad comprometida')


def mandar_mensaje(socket, mensaje):
    """
    Manda un mensaje tomando en cuenta el delimitador.

    Keyword Arguments:
    socket es el socket de servidor o cliente destino
    mensaje bytes de mensaje
    returns: None
    """
    # generar iv aleatorio
    # cifrar con aead antes de enviar
    # autenticar iv
    # pegar cifrado con iv (el iv son los datos adicionales también)
    socket.send(mensaje + DELIMITADOR)


def mandar_archivo(socket, path, aes):
    #se envie el archivo a la ruta a subir
    nonce = os.urandom(12)
    mensaje = b''
    add = b'datos adicionales random para aes gcm'
    encryptor = Cipher(algorithms.AES(aes), modes.GCM(
        nonce), backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(add)

    #ct es el mensaje cifrado
    ct = b''
    for buffer in open(path, "rb"):
        data = encryptor.update(buffer)
        ct += data

    encryptor.finalize()
    tag = encryptor.tag
    mensaje = nonce+nonce+tag+ct  # * 12,16,16 bytes
    socket.send(mensaje)
    socket.send(DELIMITADOR)


def mandar_firmas_clientes(firmas, socket):
    socket.send(firmas+DELIMITADOR)
