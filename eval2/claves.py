import os
from typing import Tuple, Union

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Genera un par de claves RSA (privada y pública).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return clave_privada, clave_privada.public_key()


def save_pem(key_or_pem: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str],path: str,contrasena: bytes | None = None):
    """
    Guarda una clave RSA en formato PEM.
    - Si se recibe una clave privada y se escribe la 'contrasena',
      la clave se guarda cifrada en disco.
    - La clave pública  se guarda en texto claro.
    - Si recibe bytes o string, se escriben directamente.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Convertir la contraseña a bytes si viene como string
    if isinstance(contrasena, str):
        contrasena = contrasena.encode("utf-8")

    # Si es contenido ya serializado, escribirlo directamente
    if isinstance(key_or_pem, (bytes, bytearray)):
        pem_bytes = key_or_pem

    # Si viene como string, convertirlo a bytes
    elif isinstance(key_or_pem, str):
        pem_bytes = key_or_pem.encode("utf-8")

    # Si es una clave privada RSA → serializarla en formato PKCS8
    elif hasattr(key_or_pem, "private_bytes"):
        encryption = (
            serialization.BestAvailableEncryption(contrasena)
            if contrasena else serialization.NoEncryption()
        )
        pem_bytes = key_or_pem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    # Si es una clave pública RSA → serializar sin cifrar
    elif hasattr(key_or_pem, "public_bytes"):
        pem_bytes = key_or_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    else:
        raise TypeError(
            "Objeto no reconocido: se esperaba clave RSA o bytes PEM")

    # Escribir el archivo .pem
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_pem(path: str, contrasena: bytes | None = None):
    """
    Carga una clave RSA desde un archivo PEM.
    - Si el archivo contiene una clave privada cifrada,
      será necesario proporcionar la contraseña.
    - Si la contraseña no es se intenta interpretar el contenido como clave
    pública.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo: {path}")

    with open(path, "rb") as f:
        data = f.read()

    try:
        # Intentar cargar como clave privada
        return serialization.load_pem_private_key(
            data,
            password=contrasena,
            backend=default_backend()
        )
    except ValueError:
        # Si falla, interpretarlo como clave pública
        return serialization.load_pem_public_key(
            data,
            backend=default_backend()
        )


def generar_y_guardar_claves(nombre: str, contrasena: str):
    """
    Genera el par de claves RSA del usuario y las guarda en disco.
    """
    # Crear la carpeta del usuario si no existe
    user_dir = os.path.join("data/keys", nombre)
    os.makedirs(user_dir, exist_ok=True)

    # Generar las dos claves
    private_key, public_key = generate_rsa_keypair()

    # Serializar la clave privada,cifrada con la contraseña del usuario
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            contrasena.encode("utf-8")
        )
    )

    # Serializar la clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar ambos archivos
    with open(os.path.join(user_dir, "private.pem"), "wb") as f:
        f.write(private_pem)

    with open(os.path.join(user_dir, "public.pem"), "wb") as f:
        f.write(public_pem)

    return private_key

