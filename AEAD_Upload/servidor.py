import socket
import threading
import sys
import os
import functools
import mensajes
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


USUARIOS = {'carlos': 'ramsses619', 'sahib1': 'pressure11'}


def crear_socket_servidor(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # hace el bind en cualquier interfaz disponible
    servidor.bind(('', int(puerto)))
    return servidor


def listar_archivos(directorio_path):
    lista_archivos = os.listdir(directorio_path)
    lista_binaria = [ar.encode('utf-8') for ar in lista_archivos]
    res = functools.reduce(lambda s1, s2: s1 + b'\n' + s2, lista_binaria)
    return res


def enviar_lista_archivos(cliente, directorio):
    mensajes.mandar_mensaje(cliente, listar_archivos(directorio))


def regregar_menu_usuario():
    return b"""
    Opciones disponibles:
    1) Listar archivos (ejemplo: 1)
    2) Descargar archivo (indicar nombre, ejemplo: 2 arichivo.txt)
    3) Subir archivo (indicar ruta local, ejemplo: 3 /path/archivo)
    4) Terminar conexion
    """


def descargar_archivo(cliente, carpeta_c, mensaje,aes_enviar):
    """
    Funcionalidad para que los clientes descarguen un archivo
    """
    partes = mensaje.split(b' ')
    if len(partes) != 2:
        mensajes.mandar_mensaje(cliente, b'Malos argumentos')
        return
    nombre_archivo = partes[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    if not nombre_archivo in os.listdir(carpeta_c):
        mensajes.mandar_mensaje(cliente, b'No existe el archivo')
        return
    mensajes.mandar_mensaje(cliente, b'OK')
    mensajes.leer_mensaje(cliente)
    mensajes.mandar_archivo(
        cliente, carpeta_c + '/' + nombre_archivo,aes_enviar)


def subir_achivo(cliente, carpeta_c, mensaje,aes_recibir):
    """
    Funcionalidad para que los clientes puedan subir archivos al repo
    """
    partes = mensaje.split(b' ')
    if len(partes) != 2:
        mensajes.mandar_mensaje(cliente, b'Malos argumentos')
        return
    nombre_archivo = partes[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    nombre_archivo = nombre_archivo.split('/')[-1].strip()
    if nombre_archivo in os.listdir(carpeta_c):
        mensajes.mandar_mensaje(cliente, b'Ya existe el archivo')
        return
    mensajes.mandar_mensaje(cliente, b'OK')
    mensajes.leer_archivo(cliente, carpeta_c + '/' +
                          nombre_archivo,aes_recibir)
    mensajes.mandar_mensaje(cliente, b'OK')


def leer_opcion(cliente, carpeta_c,aes_recibir,aes_enviar):
    """
    Determina la acción de cliente a ejecutar.

    Keyword Arguments:
    cliente --
    returns: None
    """
    mensaje = mensajes.leer_mensaje(cliente)
    if mensaje.startswith(b'1'):
        enviar_lista_archivos(cliente, carpeta_c)
    if mensaje.startswith(b'2'):
        descargar_archivo(cliente, carpeta_c, mensaje,aes_enviar)
    if mensaje.startswith(b'3'):
        subir_achivo(cliente, carpeta_c, mensaje,aes_recibir)
    resultado = mensajes.leer_mensaje(cliente)
    print(resultado.decode('utf-8'))


def llave_deserealizar(llave):
    llave_final = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_final


def secreto(dhclient, dh_privada):
    secret = dh_privada.exchange(ec.ECDH(), dhclient)

    return secret


def derivar_llave(secret):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secret)
    return derived_key


def descifrar_mensaje(cifrado, llave_aes):
    iv = cifrado[0:12]
    cifrado = cifrado[12:]
    aad = cifrado[0:32]
    cifrado = cifrado[32:]
    mc = cifrado
    chacha = ChaCha20Poly1305(llave_aes)
    mensaje = chacha.decrypt(iv, mc, aad)
    return mensaje


def atencion(cliente, carpeta_c):
    mensaje = mensajes.leer_mensaje(cliente)
    if mensaje.startswith(b'DHCLI'):
        dhpub_s = mensaje[5:]
        dhpub = llave_deserealizar(dhpub_s)
        secreto_recep = secreto(dhpub, dh_privada)
        secreto_rec = secreto_recep[:24]
        secreto_env = secreto_recep[24:]

        aes_recibir = derivar_llave(secreto_rec)
        aes_enviar = derivar_llave(secreto_env)
        key = derivar_llave(secreto_recep[:32])
        creden = mensaje[-77:]
        creds = descifrar_mensaje(creden, key)
        credencialesU = creds.decode('utf-8')
        username = credencialesU.split(':')[0]
        password = credencialesU.split(':')[1]

        try:
            if username in USUARIOS.keys():
                if password == USUARIOS[username]:
                    print(f'**{username} conectado**')
                else:
                    print(f'**{username} contraseña inválida**')
                    msg = b"FINCONEXION"
                    mensajes.mandar_mensaje(cliente, msg)
                    quit()
            else:
                print(f'**{username} inválido**')
                msg = b"FINCONEXION"
                mensajes.mandar_mensaje(cliente, msg)
                quit()
        except Exception as e:
            print(e)
    while True:
        # Rutina para intercambio ECDH (se limita a un solo cliente)
        # autenticar a usuario después de intercambriar llaves
        mensajes.mandar_mensaje(cliente, regregar_menu_usuario())
        leer_opcion(cliente, carpeta_c,aes_recibir,aes_enviar)


def llave_serializar(llave):
    llaveS = llave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llaveS


def escuchar(servidor, carpeta_c, dh_publica):
    servidor.listen(5)  # peticiones de conexion simultaneas
    while True:
        cliente, _ = servidor.accept()
        pub_dhserv = llave_serializar(dh_publica)
        servpubec = llave_serializar(ec_public)

        signature = ec_privada.sign(
            pub_dhserv, ec.ECDSA(hashes.SHA256()))

        sign = b'SIGNTR' + pub_dhserv + servpubec + signature
        mensajes.mandar_mensaje(cliente, sign)

        hiloAtencion = threading.Thread(target=atencion, args=(
            cliente, carpeta_c))  # se crea un hilo de atención por cliente
        hiloAtencion.start()

if __name__ == '__main__':
    puerto = sys.argv[1]
    carpeta_c = sys.argv[2]
    servidor = crear_socket_servidor(puerto)
    print('Escuchando...')
    ec_privada = ec.generate_private_key(ec.SECP384R1(), default_backend())
    ec_public = ec_privada.public_key()
    
    dh_privada = ec.generate_private_key(ec.SECP384R1(), default_backend())
    dh_publica = dh_privada.public_key()
    escuchar(servidor, carpeta_c, dh_publica)
