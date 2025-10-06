import os,json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Archivo donde guardaremos usuarios y hashes
DB_PATH = "usuarios.json"

# Genera un hash seguro de una contraseña
def derivar(salt: bytes) -> bytes:
    """
    Deriva un hash de la contraseña usando Scrypt de la librería cryptography.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    #Convierte la contrasñea que esta en formato texto en bytes
    key = kdf.derive(b"my great password")  
    return key

def registrar(nombre:str,contraseña:str):
    salt=os.urandom(16)
    hash_generado=derivar(salt)
     # Leemos la base de datos (archivo JSON)
    usuarios = {}
    if os.path.exists(usuarios.json):
        with open(usuarios.json, "r", encoding="utf-8") as f:
            usuarios = json.load(f)

    # Comprobamos si el usuario ya existe
    if nombre in usuarios:
        raise ValueError("El usuario ya existe.")

    # Guardamos salt y hash codificados en hexadecimal
    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
        "n": 2**14,
        "r": 8,
        "p": 1,
    }

    # Escribimos el archivo de nuevo
    with open(usuarios.json, "w", encoding="utf-8") as f:
        json.dump(usuarios, f,ensure_ascii=False)

    print("Usuario registrado correctamente ")
    