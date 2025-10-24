import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from eval1.cifrado_descifrado import generate_rsa_keypair

""" Archivo donde se guardan los usuarios, sus salt y hash de contraseña """
RUTA_USUARIOS = "data/usuarios.json"


def derivar_clave(contraseña: str, salt: bytes) -> bytes:
    """ Usamos Scrypt para derivar una clave de 32 bytes a partir de la
    contraseña y un salt """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(contraseña.encode("utf-8"))


def verificar_clave(contraseña: str, salt: bytes, hash_guardado: bytes) -> bool:
    """ Verificamos si el hash de la contraseña introducida coincide con el
    hash almacenado """
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(contraseña.encode("utf-8"), hash_guardado)
        return True
    except InvalidKey:
        return False


def registrar(nombre: str, contraseña: str):
    """ Generamos un salt aleatorio y derivamos el hash de la contraseña con ese salt """
    salt = os.urandom(16)
    hash_generado = derivar_clave(contraseña, salt)

    """ Cargamos los usarios existentes y verificamos que el nombre no se 
    repita """
    usuarios = {}
    if os.path.exists(RUTA_USUARIOS):
        with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)
    if nombre in usuarios:
        raise ValueError("El usuario ya existe")

    """ Guardamos el salt y el hash en el JSON """
    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
    }

    """ Creamos carpetas para almacenar las claves del usuario """
    os.makedirs("data/keys", exist_ok=True)
    user_dir = os.path.join("data/keys", nombre)
    os.makedirs(user_dir, exist_ok=True)

    """ Generamos claves RSA usando la contraseña como semilla """
    private_key, public_key = generate_rsa_keypair(contraseña.encode("utf-8"))

    """ Serializamos clave privada (cifrada con contraseña) """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(contraseña.encode("utf-8"))
    )

    """ Serializamos clave pública """
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    """ Guardamos PEMs en disco """
    with open(os.path.join(user_dir, "private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(user_dir, "public.pem"), "wb") as f:
        f.write(public_pem)

    with open(RUTA_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)

    print(f"Usuario {nombre} registrado correctamente con claves RSA generadas.")


def autenticar(nombre: str, contraseña: str) -> bool:
    """ Verificamos que haya usuarios registrados """
    if not os.path.exists(RUTA_USUARIOS):
        print("No hay usuarios registrados aún")
        return False

    """ Cargamos los usuarios y verificamos que el nombre exista """
    with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
        usuarios = json.load(f)
    if nombre not in usuarios:
        print("Usuario no encontrado.")
        return False

    """ Recuperamos salt y hash para verificar si la contraseña introducida 
    es correcta """
    salt = bytes.fromhex(usuarios[nombre]["salt"])
    hash_guardado = bytes.fromhex(usuarios[nombre]["hash"])
    if verificar_clave(contraseña, salt, hash_guardado):
        print("Los datos son correctos")
        return True
    else:
        print("Contraseña incorrecta.")
        return False