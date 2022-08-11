import hashlib

file = open('testing.txt', 'bw')
file.write(b'algun texto')
file.close()
file = open('testing.txt', 'br')
content_global = file.read()
file.close()
print(content_global)

alf = "abcdefghijklmnopqrstuvwxyz"
af = list(alf)
alfabeto = []
print(af)

for char in af:
    alfabeto.append(ord(char))

print(alfabeto)

def cifrar(content, shift, alfabeto):
    data = list(content) #se crea una lista en unicode con el contenido en binario
    res = []

    print(f'Unicode inicial {data}')

    for char in data: # ciclo para aumentar el shift al unicode y cambiar el valor inicial
        if char in alfabeto:
            new_char = alfabeto[((alfabeto.index(char) + shift) % 26)]
            res.append(new_char)
        else:
            res.append(char)
    print(f'Unicode shifteado {res}')

    return bytes(res)

def decifrar(content, shift, alfabeto):
    data = list(content) #se crea una lista en unicode con el contenido en binario
    res = []

    print(f'Unicode inicial cifrado {data}')

    for char in data: # ciclo para aumentar el shift al unicode y cambiar el valor inicial
        if char in alfabeto:
            new_char = alfabeto[((alfabeto.index(char) - shift) % 26)]
            res.append(new_char)
        else:
            res.append(char)
    print(f'Unicode shifteado decifrado {res}')

    return bytes(res)

def integrity(decoded_hash, og_hash):
    if decoded_hash == og_hash:
        return True
    else:
        return False

def cifrarArchivo(path_in, path_out, shift):

    file = open(path_in, 'br')
    content = file.read()
    file.close()

    #hasheamos el contenido del txt
    hasher = hashlib.sha256()
    hasher.update(content) 
    binhash = hasher.digest() #bytes hash

    #unimos el hash con el contenido para cifrarlo todo
    cont = binhash + content
    print(f'Contenido inicial {cont}')

    #ciframos el contenido
    cifrado = cifrar(cont, shift, alfabeto) 
    file2 = open(path_out, 'bw')
    file2.write(cifrado) #Después escribimos el mismo contenido pero cifrado con el hash
    file.close()

def decifrarArchivo(path_in, path_out, shift):

    file = open(path_in, 'br')
    content = file.read()
    file.close()

    #Decifrar contenido y quedarnos con el hash
    cifrado = decifrar(content, shift, alfabeto)
    hash_unique = cifrado[:32]
    print(hash_unique)

    #quedarnos con el contenido binario
    content_unique = cifrado[32:]
    print(content_unique)

    #hasheamos el contenido del txt
    hasher = hashlib.sha256()
    hasher.update(content_unique)
    binhash = hasher.digest() #bytes hash

    #Se verifica si el contenido sufrió algún cambio
    if integrity(hash_unique, binhash) == True:
        file2 = open(path_out, 'bw')
        file2.write(content_unique)
        file.close()
        print("La integridad fue verificada exitosamente")
    else:
        raise RuntimeError(f'Los datos del archivo {path_in} han sido corrompidos')
    
path_in = "./testing.txt"
path_out = "./testingcode.txt"

cifrarArchivo(path_in, path_out, 20)

# path_in = "./testingcode.txt"
# path_out = "./testingdecode.txt"

# decifrarArchivo(path_in, path_out, 20)