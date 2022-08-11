
import socket
import threading
import sys
from time import sleep
from cryptography.hazmat.primitives import serialization
import mensajes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

def conectar_servidor(host, puerto):
    # socket para IP v4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()


def leer_menu(cliente):
    """
    Lee el menú principal que manda el servidor y lo imprime.

    Keyword Arguments:
    cliente --
    returns: None
    """
    menu = mensajes.leer_mensaje(cliente)
    if menu == b"FINCONEXION":
        print("Conexion Rechazada")
        quit()
    else:
        print(menu.decode('utf-8'))


def procesar_listar_archivos(cliente, comando):
    mensajes.mandar_mensaje(cliente, comando)
    respuesta = mensajes.leer_mensaje(cliente)
    print(respuesta.decode('utf-8'))
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_descargar_archivo(cliente, comando, path_salida,aes_recibir):
    mensajes.mandar_mensaje(cliente, comando)
    mensaje = mensajes.leer_mensaje(cliente)
    if not b'OK' in mensaje:
        print(mensaje.decode('utf-8'))
        mensajes.mandar_mensaje(cliente, b'Fin')
        return
    nombre_archivo = comando.split(b' ')[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    print(f'Archivo descargado con éxito: {path_salida}')
    mensajes.mandar_mensaje(cliente, b'Continue')
    mensajes.leer_archivo(cliente, path_salida + '/' + nombre_archivo,aes_recibir)
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_subir_archivo(cliente,path_salida, comando, aes_enviar):
    mensajes.mandar_mensaje(cliente, comando)
    mensaje = mensajes.leer_mensaje(cliente)
    if not b'OK' in mensaje:
        print(mensaje.decode('utf-8'))
        mensajes.mandar_mensaje(cliente, b'Fin')
        return
    path = comando.split(b' ')[1].strip()
    path = path_salida + '/' + path.decode('utf-8')
    print(f'Archivo subido con éxito: {path}')
    mensajes.mandar_archivo(cliente, path, aes_enviar)
    mensajes.leer_mensaje(cliente)
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_comando(cliente, comando, path_ref,aes_enviar,aes_recibir):
    """
    Rutina para decidir las acciones a tomar de acuerdo al comando.
    """
    if comando.startswith(b'1'):
        os.system('clear')
        print("Archivos Disponibles:")
        procesar_listar_archivos(cliente, comando)
        return
    if comando.startswith(b'2'):
        os.system('clear')
        procesar_descargar_archivo(cliente, comando, path_ref,aes_recibir)
        return
    if comando.startswith(b'3'):
        os.system('clear')
        procesar_subir_archivo(cliente, path_ref,  comando,aes_enviar)
        return
    if comando.startswith(b'4'):
        os.system('clear')
        print("Conexión finalizada.")
        quit()


def deserealizar_llave(llave):
    llave_deserealizada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_deserealizada


def check(servpub_ec, signature, dh_servidor_pub_S):
    try:
        servpub_ec.verify(signature, dh_servidor_pub_S, ec.ECDSA(hashes.SHA256()))
        print('FIRMA VALIDA')
    except:
        print('FIRMA NO VALIDA')
        quit()


def serializar_llave(llave):
    llave_serializada = llave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llave_serializada


def exchange(dh_servidor_pub, dh_cliente_priv):
    secreto_emisor = dh_cliente_priv.exchange(ec.ECDH(), dh_servidor_pub)
    return secreto_emisor


def derivar_llave(secreto_emisor):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secreto_emisor)
    return derived_key


def env_cif(mensaje_plano, aes_key):
    aad = b'mensaje de datos adicionales 32b'
    iv = os.urandom(12)
    plano = mensaje_plano

    chacha = ChaCha20Poly1305(aes_key)
    mensaje_cifrado = chacha.encrypt(iv, plano, aad)
    return (iv+aad+mensaje_cifrado)


def work_loop(cliente, path_ref, dh_cliente_pub):
    """
    Trabajo principal
    """
    mensaje = mensajes.leer_mensaje(cliente)
    if mensaje.startswith(b'SIGNTR'):
        firmas = mensaje[6:]
        servdhpub = firmas[:215]
        servecpub = firmas[215:430]
        signature = firmas[430:]

        servpub_ec = deserealizar_llave(servecpub)

        #Verificamos si la firma es válida
        check(servpub_ec, signature, servdhpub)

        pubdh = serializar_llave(dh_cliente_pub)
        pubdh = b'DHCLI'+pubdh

        dh_servidor_pub = deserealizar_llave(servdhpub)
        secreto_emisor = exchange(dh_servidor_pub, privdh)
        secreto_enviar = secreto_emisor[:24]
        secreto_recibir = secreto_emisor[24:]

        #LLAVES CLIENTE
        aes_recibir = derivar_llave(secreto_recibir)
        aes_enviar = derivar_llave(secreto_enviar)
        key = derivar_llave(secreto_emisor[:32])

        #CREDENCIALES
        user = input("Tecle tu nombre de Usuario: ")
        passwd = input("Tecle tu nombre de Contraseña: ")
        mensaje = f'{user}:{passwd}'
        mensaje = mensaje.encode('utf-8')
        credenciales = env_cif(mensaje, key)
        mensajes.mandar_mensaje(cliente, pubdh+b'////'+credenciales)
    else:
        print('No se encontraron firmas')
        quit()
    while True:
        leer_menu(cliente)
        comando = input('Selecciona comando: ')
        comando = comando.encode('utf-8')
        procesar_comando(cliente, comando, path_ref,aes_enviar,aes_recibir)

if __name__ == '__main__':
    host = sys.argv[1]
    puerto = sys.argv[2]
    path_ref = sys.argv[3]
    cliente = conectar_servidor(host, puerto)

    privdh =  ec.generate_private_key(ec.SECP384R1(), default_backend())
    pubdh = privdh.public_key()
    work_loop(cliente, path_ref, pubdh)
