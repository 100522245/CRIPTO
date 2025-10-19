import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

# Archivo donde guardaremos los usuarios y hashes
RUTA_USUARIOS = "data/usuarios.json"

# ======== FUNCIONES AUXILIARES ========

def derivar_clave(contraseña: str, salt: bytes) -> bytes:
    """
    Deriva una clave (hash) segura de una contraseña usando Scrypt.
    """
    kdf = Scrypt(
        salt=salt,  #Valor que se usa para asegurar que dos usuarios no
        # tengan el mismo hash
        length=32,  # Longitud del hash en bytes
        n=2**14,    # Parámetro de coste (mayor = más seguro, pero más lento)
        r=8,
        p=1,
    )
    #Convierte la contraseña a bytes
    return kdf.derive(contraseña.encode("utf-8"))


def verificar_clave(contraseña: str, salt: bytes, hash_guardado: bytes) -> bool:
    """
    Verifica si la contraseña ingresada genera el mismo hash que el guardado.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    try:
        #Usa verify para comprobar el hash
        kdf.verify(contraseña.encode("utf-8"), hash_guardado)
        #Si coinciden devuelve true
        return True
    except InvalidKey:
        #Si no coinciden devuelve una excepcion
        return False


# ======== FUNCIONES PRINCIPALES ========

def registrar(nombre: str, contraseña: str):
    """
    Registra un nuevo usuario y almacena su hash y salt.
    """
    # Crea un salt aleatorio (único por usuario)
    salt = os.urandom(16)
    hash_generado = derivar_clave(contraseña, salt)

    # Carga el json con todos los usuarios
    usuarios = {}
    if os.path.exists(RUTA_USUARIOS):
        with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)

    # Verifica si el usuario ya existe
    if nombre in usuarios:
        raise ValueError("El usuario ya existe")

    # Guarda el usuario con su salt y hash (en formato hexadecimal)
    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
    }

    # Escribe el archivo actualizado
    with open(RUTA_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)

    print("Usuario",nombre,"registrado correctamente")


def autenticar(nombre: str, contraseña: str) -> bool:
    """
    Autentica un usuario verificando su contraseña.
    """
    #Comprueba que el archivo de usuarios existe
    if not os.path.exists(RUTA_USUARIOS):
        print("No hay usuarios registrados aún")
        return False

    #Carga los datos del json
    with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
        usuarios = json.load(f)

    # Verifica si el usuario existe
    if nombre not in usuarios:
        print("Usuario no encontrado.")
        return False

    # Recupera los valores guardados
    salt = bytes.fromhex(usuarios[nombre]["salt"])
    hash_guardado = bytes.fromhex(usuarios[nombre]["hash"])

    # Verifica la contraseña
    if verificar_clave(contraseña, salt, hash_guardado):
        print("Los datos son correctos")
        return True
    else:
        print("Contraseña incorrecta.")
        return False



