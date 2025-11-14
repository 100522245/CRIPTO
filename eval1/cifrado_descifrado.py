import os
import json
import base64
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


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


def save_pem(
    key_or_pem: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str],
    path: str,
    contrasena: bytes | None = None
):
    """
    Guarda una clave (privada o pública) en formato PEM.
    Si es privada y tiene contraseña → se guarda cifrada.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if isinstance(contrasena, str):
        contrasena = contrasena.encode("utf-8")

    if isinstance(key_or_pem, (bytes, bytearray)):
        pem_bytes = key_or_pem
    elif isinstance(key_or_pem, str):
        pem_bytes = key_or_pem.encode("utf-8")
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
    elif hasattr(key_or_pem, "public_bytes"):
        pem_bytes = key_or_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise TypeError("Objeto no reconocido: se esperaba clave RSA o bytes PEM")

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
        return serialization.load_pem_private_key(
            data,
            password=contrasena,
            backend=default_backend()
        )
    except ValueError:
        return serialization.load_pem_public_key(data, backend=default_backend())


# ==================== FIRMA DIGITAL ====================

def firmar_mensaje(mensaje: bytes, rsa_private_pem: bytes, passphrase: bytes | None = None) -> bytes:
    """
    Firma un mensaje usando RSA-PSS con SHA256.
    Devuelve la firma como bytes.
    """
    private_key = serialization.load_pem_private_key(
        rsa_private_pem,
        password=passphrase,
        backend=default_backend()
    )

    firma = private_key.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return firma


def verificar_firma_mensaje(mensaje: bytes, firma: bytes, rsa_public_pem: bytes) -> bool:
    """
    Verifica una firma RSA-PSS con SHA256.
    Devuelve True si la firma es válida, False si no.
    """
    public_key = serialization.load_pem_public_key(
        rsa_public_pem,
        backend=default_backend()
    )

    try:
        public_key.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ==================== CIFRADO / DESCIFRADO (AES-GCM + RSA-OAEP) ====================

def encrypt_reserva(
    reserva_bytes: bytes,
    rsa_public_pem: bytes,
    aad: bytes = b"",
    firma: bytes | None = None
) -> bytes:
    """
    Cifra datos usando:
      - AES-GCM (clave simétrica): cifra los datos y genera TAG.
      - RSA-OAEP (clave pública): cifra la clave AES.
    Además, adjunta opcionalmente una FIRMA (RSA-PSS+SHA256) en el JSON.

    Devuelve un JSON (en bytes) con:
        algoritmo, clave_aes_cifrada, nonce, ciphertext, aad, firma?
    """
    # 1) Clave AES
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)

    # 2) Nonce
    nonce = os.urandom(12)

    # 3) Cifrado autenticado
    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    # 4) Cifrado de la clave AES con la pública RSA
    clave_publica = serialization.load_pem_public_key(rsa_public_pem)
    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # 5) Payload JSON
    payload = {
        "algoritmo": "AES-GCM+RSA-OAEP",
        "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
    }

    if firma is not None:
        payload["firma"] = base64.b64encode(firma).decode("ascii")

    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decrypt_reserva(
    encrypted_json: bytes,
    rsa_private_pem: bytes,
    passphrase: bytes
) -> Tuple[bytes, bytes | None]:
    """
    Descifra datos generados por encrypt_reserva().
      1) Descifra la clave AES con la clave privada RSA.
      2) Usa AES-GCM para descifrar y verificar autenticidad.
      3) Devuelve (plaintext, firma) → la firma puede ser None si no existe.

    Devuelve:
        (datos_en_claro: bytes, firma: bytes | None)
    """
    # 1) Parseo JSON
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado o corrupto") from e

    # 2) Decodificación base64
    clave_aes_cifrada = base64.b64decode(payload.get("clave_aes_cifrada", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))
    firma_b64 = payload.get("firma")
    firma = base64.b64decode(firma_b64) if firma_b64 else None

    # 3) Clave privada RSA
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

    # 4) Descifrar clave AES
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

    # 5) Descifrar contenido AES-GCM
    try:
        aesgcm = AESGCM(clave_aes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext, firma
    except Exception as e:
        raise ValueError("Error al descifrar el contenido AES-GCM") from e
