# cifrado_descifrado.py
import os
import json
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption


def generate_rsa_keypair(passphrase: bytes, key_size: int = 2048) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    encryption_alg = BestAvailableEncryption(passphrase) if passphrase else NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg,
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def encrypt_reserva(reserva_bytes: bytes, rsa_public_pem: bytes, aad: bytes = b"") -> bytes:
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    public_key = serialization.load_pem_public_key(rsa_public_pem)
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    payload = {
        "algorithm": "AES-GCM+RSA-OAEP",
        "aes_key_encrypted": base64.b64encode(enc_aes_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "aes_key_length": 256,
    }

    return json.dumps(payload, indent=2).encode("utf-8")


def decrypt_reserva(encrypted_json: bytes, rsa_private_pem: bytes, passphrase: bytes) -> bytes:
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado") from e

    enc_aes_key = base64.b64decode(payload.get("aes_key_encrypted", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))

    try:
        private_key = serialization.load_pem_private_key(rsa_private_pem, password=passphrase)
    except Exception as e:
        raise ValueError("No se pudo cargar la clave privada (passphrase incorrecta o PEM inválido)") from e

    try:
        aes_key = private_key.decrypt(
            enc_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception as e:
        raise ValueError("Fallo al descifrar la clave AES con RSA") from e

    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        raise ValueError("Fallo al descifrar el contenido AES-GCM (integridad inválida o parámetros incorrectos)") from e


def save_pem(path: str, pem_bytes: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()