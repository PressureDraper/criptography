file = open('testing.txt', 'w')
file.write('algun texto')
file.close()

alf = "abcdefghijklmnopqrstuvwxyz"
af = list(alf)
alfabeto = []
print(af)

for char in af:
    alfabeto.append(ord(char))

print(alfabeto)

def cifrar(content, shift, alfabeto):
    data = list(content) #se crea una lista char con el contenido
    unicode = []
    res = []
    new_text = []
    text = ''

    for char in data: #cambiamos cada char a unicode y se agrega al array
        unicode.append(ord(char))
    print(unicode)

    for char in unicode: # ciclo para aumentar el shift al unicode y cambiar el valor inicial
        if char in alfabeto:
            new_char = alfabeto[((alfabeto.index(char) + shift) % 26)]
            res.append(new_char)
        else:
            res.append(char)
    print(res)

    for newchar in res: # ciclo para añadir al array los nuevos carácteres
        new_text.append(chr(newchar))
    
    print(new_text)

    #convirtiendo array a str
    text = text.join(new_text)

    return text

def decifrar(content, shift, alfabeto):
    data = list(content) #se crea una lista char con el contenido
    unicode = []
    res = []
    new_text = []
    text = ''

    for char in data: #cambiamos cada char a unicode y se agrega al array
        unicode.append(ord(char))
    print(unicode)

    for char in unicode: # ciclo para disminuir el shift al unicode y cambiar el valor al inicial
        if char in alfabeto:
            new_char = alfabeto[((alfabeto.index(char) - shift) % 26)]
            res.append(new_char)
        else:
            res.append(char)
    print(res)

    for newchar in res: # ciclo para añadir al array los nuevos carácteres
        new_text.append(chr(newchar))
    
    print(new_text)

    #convirtiendo array a str
    text = text.join(new_text)

    return text

def cifrarArchivo(path_in, path_out, shift):

    file = open(path_in, 'r')
    content = file.read()
    file.close()
    cifrado = cifrar(content, shift, alfabeto)
    file2 = open(path_out, 'w')
    file2.write(cifrado)
    file.close()

def decifrarArchivo(path_in, path_out, shift):

    file = open(path_in, 'r')
    content = file.read()
    file.close()
    cifrado = decifrar(content, shift, alfabeto)
    file2 = open(path_out, 'w')
    file2.write(cifrado)
    file.close()

#------------------MAIN---------------------
path_in = "./testing.txt"
path_out = "./testingcode.txt"

cifrarArchivo(path_in, path_out, 20)

"""path_in = "./testingcode.txt"
path_out = "./testingdecode.txt"

decifrarArchivo(path_in, path_out, 20)"""