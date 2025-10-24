# cifrado_descifrado.py
import os
import json
import base64
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ============================================================
# 🔐 GENERACIÓN DE CLAVES RSA
# ============================================================
def generate_rsa_keypair(passphrase: bytes | None = None, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Genera un par de claves RSA (privada, pública).
    El parámetro passphrase no se usa en la generación,
    solo puede ser útil para serializar después.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


# ============================================================
# 💾 GUARDAR Y CARGAR CLAVES RSA
# ============================================================
def save_pem(key_or_pem: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str],
             path: str,
             password: bytes | None = None):
    """
    Guarda una clave (privada o pública) en formato PEM.
    Acepta tanto objetos de clave como bytes/str PEM.
    """
    """ Creamos la carpeta si no existe """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    """ Convertimos la contraseña a bytes si es string """
    if isinstance(password, str):
        password = password.encode("utf-8")

    """ Si ya es PEM lo guardamos directamente """
    if isinstance(key_or_pem, (bytes, bytearray)):
        pem_bytes = key_or_pem
    elif isinstance(key_or_pem, str):
        pem_bytes = key_or_pem.encode("utf-8")
    elif hasattr(key_or_pem, "private_bytes"):
        """ Serializamos clave privada """
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )
        pem_bytes = key_or_pem.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    elif hasattr(key_or_pem, "public_bytes"):
        """ Serializamos clave pública """
        pem_bytes = key_or_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise TypeError("Objeto no reconocido: se esperaba clave RSA o bytes PEM")

    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_pem(path: str, password: bytes | None = None):
    """
    Carga una clave RSA desde un archivo PEM (privada o pública).
    Si está cifrada, requiere 'password'.
    Devuelve el objeto de clave.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontró el archivo: {path}")

    with open(path, "rb") as f:
        data = f.read()

    try:
        return serialization.load_pem_private_key(data, password=password, backend=default_backend())
    except ValueError:
        return serialization.load_pem_public_key(data, backend=default_backend())


# ============================================================
# 🔒 CIFRADO Y DESCIFRADO DE DATOS (AES-GCM + RSA-OAEP)
# ============================================================
def encrypt_reserva(reserva_bytes: bytes, rsa_public_pem: bytes, aad: bytes = b"") -> bytes:
    """
    Cifra datos usando un esquema híbrido:
    AES-GCM para los datos, RSA-OAEP para la clave simétrica.
    Devuelve un JSON codificado en UTF-8.
    """
    """ Generamos clave simétrica y ciframos los datos """
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    """ Ciframos la clave AES con la clave pública RSA """
    public_key = serialization.load_pem_public_key(rsa_public_pem)
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    """ JSON codificado """
    payload = {
        "algorithm": "AES-GCM+RSA-OAEP",
        "aes_key_encrypted": base64.b64encode(enc_aes_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "aes_key_length": 256,
    }

    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decrypt_reserva(encrypted_json: bytes, rsa_private_pem: bytes, passphrase: bytes) -> bytes:
    """
    Descifra datos generados por encrypt_reserva().
    """
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado o corrupto") from e

    enc_aes_key = base64.b64decode(payload.get("aes_key_encrypted", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))

    """ Desciframos clave privada con la contraseña """
    try:
        private_key = serialization.load_pem_private_key(
            rsa_private_pem,
            password=passphrase,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError("No se pudo cargar la clave privada (contraseña incorrecta o PEM inválido)") from e

    """ RSA descifra AES """
    try:
        aes_key = private_key.decrypt(
            enc_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
    except Exception as e:
        raise ValueError("Error al descifrar la clave AES con RSA-OAEP") from e

    """ Desciframos con AES """
    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        raise ValueError("Error al descifrar el contenido AES-GCM") from e
