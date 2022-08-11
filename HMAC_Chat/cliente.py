from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import time
import socket
import threading
import sys
import json

import mensajes

def conectar_servidor(host, puerto):
    # socket para IP v4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()

def recuperarOriginal(msg):
    for elemento in msg:
        if len(elemento) == 2: #Si la longitud es = 2 entonces es el cliente, sino, son las llaves
            tp = tuple(elemento)
            llaves.append(tp)
        else:
            llave = bytes(elemento)
            llaves.append(llave)
    return llaves

def leer_mensajes(cliente):
    while True:
        mensaje = mensajes.leer_mensaje(cliente)
        msg = mensaje.decode('utf-8')
        try:
            # print(msg)
            # print(type(msg))
            #La lista recupera su formato original, pasa de ser STR a LISTA
            msg = json.loads(msg)
            # print(msg)
            # print(type(msg))

            # Convertir el unicode de las llaves a su binario respectivo y la direccion de host a su tupla respectiva para obtener
            #la misma lista que se encuentra en el servidor
            try:
                llaves.clear() #Limpiar arreglo para que no se dupliquen
            except:
                pass
            llaves = recuperarOriginal(msg)
            # print(llaves)
        except json.JSONDecodeError:
            #Procesar mensajes que no son la lista de llaves
            print(msg)

def cifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesEncryptor = aesCipher.encryptor()
    cipher = aesEncryptor.update(mensaje)
    aesEncryptor.finalize()

    return cipher

def hashedMac(mensaje, mac):
    h = hmac.HMAC(mac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)

    return h.finalize().hex()

def decifrar(mensaje, keyctr, iv):
    aesCipher = Cipher(algorithms.AES(keyctr), modes.CTR(iv), backend = default_backend())
    aesDecryptor = aesCipher.decryptor()
    mensaje = aesDecryptor.update(mensaje)
    aesDecryptor.finalize()

    return mensaje

def enviar_mensaje_loop(cliente, nick):
    #llave CTR
    keyctr = os.urandom(16)
    iv = os.urandom(16)
    mensaje = b'LLAVECTR' + keyctr
    mensajes.mandar_mensaje(cliente, mensaje)

    time.sleep(0.2)
    #llave HMAC
    b = 128 #tamaño de bloque de sha256
    mac = os.urandom(b)
    mensaje = b'HMAC' + mac
    mensajes.mandar_mensaje(cliente, mensaje)

    mensaje = b''
    while not mensaje.strip().endswith(b'exit'):
        mensaje = input(nick+': ')
        msg = f'{nick}: {mensaje}'
        mensaje = msg.encode('utf-8')
        # print(mensaje)

        # #Se obtiene el mensaje cifrado
        # mensaje = cifrar(mensaje, keyctr, iv)
        # print(mensaje)

        # #Se manda el mensaje cifrado a la funcion de hmac para aplicar hmac
        # hmacc = hashedMac(mensaje, mac)
        # print(hmacc)

        # #Decifrar para que el ciclo while detecte las palabras
        # mensaje = decifrar(mensaje, keyctr, iv)
        mensajes.mandar_mensaje(cliente, mensaje)
    
    print('Conexión cerrada.')
    cliente.close()


if __name__ == '__main__':
    host = sys.argv[1]
    puerto = sys.argv[2]
    cliente = conectar_servidor(host, puerto)
    
    #lista de llaves de clientes recuperada del servidor
    llaves = []

    nick = input('Introduce tu Nick para esta conversacion: ')
    print('Introduce "exit" para salir')

    hilo = threading.Thread(target=leer_mensajes, args=(cliente, ))
    hilo.daemon = True
    hilo.start()
    enviar_mensaje_loop(cliente, nick)
