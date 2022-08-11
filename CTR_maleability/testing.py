#Ataque de reuso de IV y llave
from encodings import utf_8
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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

def encode(decoded, key, iv):
    aesCipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend)
    aesEncryptor = aesCipher.encryptor()
    
    cipher = aesEncryptor.update(decoded)
        
    aesEncryptor.finalize()

    return cipher

def malear(texto, cifrado, cifrado2):

    #Obtenemos los primeros 64 bytes de texto del xml completo para usarlo posteriormente en xor
    textcab = texto[:64]

    #Convertimos a Unicode el cifrado original completo y la cabecera falsa
    bytes1 = list(cifrado)
    bytes2 = list(cifrado2)

    #Ahora nos quedamos con los primeros 64 bytes de la cabecera donde se encuentra el target a reemplazar
    cabecera = bytes1[:64]
    cabecerafalsa = bytes2 #ya es de 64 bytes por lo tanto unicamente se pasa igual

    # cabecera[44] = 67 #En la cabecera original los bytes del 44 al 51 son los corresponientes a Acme Inc
    # cabecera[51] = 67

    # cabecerafalsa[44] = 67 #En la cabecera falsa los bytes del 44 al 51 son los corresponientes a Evil LLC
    # cabecerafalsa[51] = 67 #Por lo tanto ya podemos reemplazar los bytes ya que ambas cabeceras son de 64 bytes

    #Obtener key stream de la cabecera original
    key_stream = calcXOR(textcab, bytes(cabecera))

    #Reemplazamos cada byte del 44 al 51 ya que sabemos que esa es la longitud en bytes del texto target
    for i in range(len(cabecera)):
        if i >= 44 and i < 52:
            cabecera[i] = cabecerafalsa[i]
    

    #Aplicar XOR a la cabecera maleada con key_stream para tener el texto plano en b
    cabecera = calcXOR(key_stream, bytes(cabecera))

    #obtenemos el texto plano completo en bytes y nos quedamos con todos aquellos despues de los 64 bytes para el cuerpo original
    cuerpo = list(texto)
    cuerpo = cuerpo[64:]

    #calculamos el XOR del texto completo en b con el cifrado completo original inicial
    key_completo = calcXOR(texto, cifrado)

    #convertimos a unicode el keystream y nos quedamos unicamente con la longitud del cuerpo
    cuerpo = list(key_completo)
    cuerpo = cuerpo[64:]

    key_cuerpo = bytes(cuerpo) #Aqui ya tenemos el key_stream del cuerpo

    #Nos quedamos con todo el cuerpo original en unicode despues de los 64 bytes de la cabecera del xml original
    cuerpocifrado = bytes1[64:]

    #Ahora obtenemos el cuerpo original en b aplicando xor con la keystream del cuerpo y el cuerpo cifrado
    cuerpo_og = calcXOR(key_cuerpo, bytes(cuerpocifrado))

    maleado = cabecera + cuerpo_og #Pegamos la cabecera maleada con el cuerpo en b y obtenemos el xml maleado
    
    return maleado.decode('utf-8')

if __name__ == "__main__":
    
    key = os.urandom(16)
    iv = os.urandom(16)

    planoXML = open("atacante.xml", "rb")
    texto = planoXML.read()
    planoXML.close()

    texto2 = b'''<XML>
  <CredictCardPurchase>
    <Merchant>Evil LLC</Merchant>\n'''

    #Obtenemos el cifrado del xml ORIGINAL
    cifrado = encode(texto, key, iv)

    #Obtenemos el cifrado del la parte que queremos reemplazar en el ORIGINAL
    cifradoModificado = encode(texto2, key, iv)

    maleado = malear(texto, cifrado, cifradoModificado)
    print(maleado)