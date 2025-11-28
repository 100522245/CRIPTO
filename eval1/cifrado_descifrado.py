import os
import json
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def encrypt_reserva(reserva_bytes: bytes,rsa_public_pem: bytes,aad: bytes = b"",firma: bytes | None = None) -> bytes:
    """
    Cifra los datos de una reserva utilizando cifrado híbrido.
    """

    # Generar una clave simétrica AES
    clave_aes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(clave_aes)

    # Generar nonce aleatorio
    # GCM requiere un nonce único por mensaje
    nonce = os.urandom(12)

    # Cifrado autenticado con AES-GCM
    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    # Cifrar la clave AES con la clave pública
    clave_publica = serialization.load_pem_public_key(rsa_public_pem)
    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Función de relleno segura
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # Construir el JSON que contiene lo necesario para descifrar
    payload = {
        "algoritmo": "AES-GCM+RSA-OAEP",  # Para identificar esquemas usados
        "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
    }

    # Si el mensaje se firmó, incluir la firma
    if firma is not None:
        payload["firma"] = base64.b64encode(firma).decode("ascii")

    # Devolver el JSON como bytes
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decrypt_reserva(encrypted_json: bytes,rsa_private_pem: bytes,passphrase: bytes) -> Tuple[bytes, bytes | None]:
    """
    Descifra un mensaje generado por encrypt_reserva().
    """

    #Convertir el JSON cifrado a estructura Python
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado o corrupto") from e

    #Extraer y decodificar todos los campos desde base64
    clave_aes_cifrada = base64.b64decode(payload.get("clave_aes_cifrada", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))

    firma_b64 = payload.get("firma")
    firma = base64.b64decode(firma_b64) if firma_b64 else None

    #Cargar la clave privada RSA cifrada con la contraseña del usuario
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

    #Recuperar la clave AES descifrando con RSA-OAEP
    try:
        clave_aes = clave_privada.decrypt(
            clave_aes_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Igual que en el cifrado
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
    except Exception as e:
        raise ValueError("Error al descifrar la clave AES con RSA-OAEP") from e

    #Descifrar el contenido con AES-GCM usando la clave recuperada
    try:
        aesgcm = AESGCM(clave_aes)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext, firma
    except Exception as e:
        raise ValueError("Error al descifrar el contenido AES-GCM") from e
