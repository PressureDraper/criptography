from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os

if __name__ == "__main__":
    b = 128 #tamaño de bloque de sha256
    entry = b'hi world!'
    k = os.urandom(b)

    h = hmac.HMAC(k, hashes.SHA256(), backend=default_backend())
    h.update(entry)
    print(h.finalize().hex())