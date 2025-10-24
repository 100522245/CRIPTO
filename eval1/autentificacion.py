# autentificacion.py
import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from eval1.cifrado_descifrado import generate_rsa_keypair, save_pem

RUTA_USUARIOS = "data/usuarios.json"


def derivar_clave(contraseña: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(contraseña.encode("utf-8"))


def verificar_clave(contraseña: str, salt: bytes, hash_guardado: bytes) -> bool:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(contraseña.encode("utf-8"), hash_guardado)
        return True
    except InvalidKey:
        return False


def registrar(nombre: str, contraseña: str):
    salt = os.urandom(16)
    hash_generado = derivar_clave(contraseña, salt)

    usuarios = {}
    if os.path.exists(RUTA_USUARIOS):
        with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)

    if nombre in usuarios:
        raise ValueError("El usuario ya existe")

    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
    }

    os.makedirs("data/keys", exist_ok=True)
    user_dir = os.path.join("data/keys", nombre)
    os.makedirs(user_dir, exist_ok=True)

    private_pem, public_pem = generate_rsa_keypair(contraseña.encode("utf-8"))
    save_pem(os.path.join(user_dir, "private.pem"), private_pem)
    save_pem(os.path.join(user_dir, "public.pem"), public_pem)

    with open(RUTA_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)

    print(f"Usuario {nombre} registrado correctamente con claves RSA generadas.")


def autenticar(nombre: str, contraseña: str) -> bool:
    if not os.path.exists(RUTA_USUARIOS):
        print("No hay usuarios registrados aún")
        return False

    with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
        usuarios = json.load(f)

    if nombre not in usuarios:
        print("Usuario no encontrado.")
        return False

    salt = bytes.fromhex(usuarios[nombre]["salt"])
    hash_guardado = bytes.fromhex(usuarios[nombre]["hash"])

    if verificar_clave(contraseña, salt, hash_guardado):
        print("Los datos son correctos")
        return True
    else:
        print("Contraseña incorrecta.")
        return False
