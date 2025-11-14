import os
import json
import base64
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Genera un par de claves RSA (privada y pública).
    La clave pública se usará para cifrar la clave AES.
    La clave privada se usará para descifrarla (autenticación del destinatario).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,   # Exponente estándar
        key_size=key_size,       # Tamaño de la clave
        backend=default_backend()
    )
    return clave_privada, clave_privada.public_key()


def save_pem(key_or_pem: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str],path: str,contrasena: bytes | None = None):
    """
    Guarda una clave (privada o pública) en formato PEM.
    Si es privada y tiene contraseña → se guarda cifrada.
    """
    # Creamos la carpeta si no existe
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Si se pasa una contraseña como texto, la convertimos a bytes
    if isinstance(contrasena, str):
        contrasena = contrasena.encode("utf-8")

    # Si ya es PEM en bytes o texto, lo guardamos directamente
    if isinstance(key_or_pem, (bytes, bytearray)):
        pem_bytes = key_or_pem
    elif isinstance(key_or_pem, str):
        pem_bytes = key_or_pem.encode("utf-8")

    # Si es una clave privada RSA → la serializamos (y la ciframos si hay password)
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

    # Si es una clave pública RSA → la serializamos sin cifrar
    elif hasattr(key_or_pem, "public_bytes"):
        pem_bytes = key_or_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise TypeError("Objeto no reconocido: se esperaba clave RSA o bytes PEM")

    # Guardamos la clave
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_pem(path: str, contrasena: bytes | None = None):
    """
    Carga una clave RSA desde un archivo PEM (privada o pública).
    Si está cifrada, requiere 'contrasena'.
    Devuelve el objeto de clave.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo: {path}")

    with open(path, "rb") as f:
        data = f.read()

    try:
        # Intentamos cargar como clave privada
        return serialization.load_pem_private_key(
            data,
            password=contrasena,
            backend=default_backend()
        )
    except ValueError:
        # Si falla, probamos como clave pública
        return serialization.load_pem_public_key(data, backend=default_backend())


def encrypt_reserva(reserva_bytes: bytes, rsa_public_pem: bytes, aad: bytes = b"") -> bytes:
    """
    Cifra datos usando:
      - AES-GCM (clave simétrica): cifra los datos y genera etiqueta de autenticación (TAG).
      - RSA-OAEP (clave pública): cifra la clave AES.

    Devuelve un JSON (bytes) con clave AES cifrada, nonce, ciphertext, aad, etc.,
    con nombres de campos en español cuando tiene sentido.
    """
    # Generamos clave simétrica AES de 256 bits
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)

    # Nonce de 12 bytes (recomendado para GCM)
    nonce = os.urandom(12)

    # Ciframos los datos y los autenticamos con AAD
    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    # Ciframos la clave AES con RSA-OAEP (clave pública del usuario)
    clave_publica = serialization.load_pem_public_key(rsa_public_pem)
    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # Construimos el payload JSON (en texto, listo para guardar)
    payload = {
        "algoritmo": "AES-GCM+RSA-OAEP",
        "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
    }

    # Devolvemos el JSON como bytes UTF-8
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decrypt_reserva(encrypted_json: bytes, rsa_private_pem: bytes, passphrase: bytes) -> bytes:
    """
    Descifra datos generados por encrypt_reserva().
      1) Descifra la clave AES con la clave privada RSA.
      2) Usa AES-GCM para descifrar y verificar autenticidad.

    Devuelve los datos en claro (bytes).
    """
    # Cargamos el JSON con los datos cifrados
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado o corrupto") from e

    # Decodificamos los campos
    clave_aes_cifrada = base64.b64decode(payload.get("clave_aes_cifrada", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))

    # Cargamos la clave privada (protegida con passphrase)
    try:
        clave_privada = serialization.load_pem_private_key(
            rsa_private_pem,
            password=passphrase,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError(
            "No se pudo cargar la clave privada (contraseña incorrecta o PEM inválido)"
        ) from e

    # Desciframos la clave AES
    try:
        clave_aes = clave_privada.decrypt(
            clave_aes_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
    except Exception as e:
        raise ValueError("Error al descifrar la clave AES con RSA-OAEP") from e

    # Desciframos el contenido con AES-GCM
    try:
        aesgcm = AESGCM(clave_aes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        raise ValueError("Error al descifrar el contenido AES-GCM") from e
