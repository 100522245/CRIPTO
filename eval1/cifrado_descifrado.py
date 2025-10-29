import os
import json
import base64
from typing import Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


#GENERACIÓN DE CLAVES RSA
def generate_rsa_keypair(passphrase: bytes | None = None, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Genera un par de claves RSA (privada y pública).
    La clave pública se usará para cifrar la clave AES.
    La clave privada se usará para descifrarla (autenticación del destinatario).
    """
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,#Exponente estandar
        key_size=key_size,#Tamaño de la clave
        backend=default_backend()
    )
    return clave_privada, clave_privada.public_key()



# GUARDAR Y CARGAR CLAVES RSA
def save_pem(key_or_pem: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str],
             path: str,
             contrasena: bytes | None = None):
    """
    Guarda una clave (privada o pública) en formato PEM.
    Si es privada y tiene contraseña → se guarda cifrada.
    """
    #Creamos la carpeta si no existe
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Si se pasa una contraseña como texto, la convertimos a bytes
    if isinstance(contrasena, str):
        contrasena = contrasena.encode("utf-8")

    # Si ya es PEM eb bytes o texto, lo guardamos directamente
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

    #Guardamps la clave
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_pem(path: str, contrasena: bytes | None = None):
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
        # Intentamos cargar como clave privada
        return serialization.load_pem_private_key(data, password=contrasena,
                                                  backend=default_backend())
    except ValueError:
        #Si falla probamos la clave publica
        return serialization.load_pem_public_key(data, backend=default_backend())


# CIFRADO Y DESCIFRADO DE DATOS (AES-GCM + RSA-OAEP)
def encrypt_reserva(reserva_bytes: bytes, rsa_public_pem: bytes, aad: bytes = b"") -> bytes:
    """
    Cifra datos usando:
      AES-GCM (clave simétrica):Cifra los datos y genera etiqueta de
      autenticación (TAG)
      RSA-OAEP (clave pública):Cifra la clave AES
    Devuelve un JSON con clave cifrada, nonce, ciphertext, aad, etc.
    """
    #Generamos clave simétrica y ciframos los datos
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    #generamos un nonce (vector de inicializacion unico por mensaje)
    nonce = os.urandom(12)

    #Ciframos los datos y los autentificamos
    #AES-GCM cifra y genera automáticamente una etiqueta (tag)
    #Si se modifica un solo bit del ciphertext o del aad, el descifrado fallará.
    ciphertext = aesgcm.encrypt(nonce, reserva_bytes, aad)

    # Ciframos la clave AES con RSA-OAEP (clave pública del usuario)
    # Esto garantiza que solo el dueño de la clave privada podrá descifrarla.
    public_key = serialization.load_pem_public_key(rsa_public_pem)
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )

    # Todos los datos en JSON codificado
    payload = {
        "algorithm": "AES-GCM+RSA-OAEP",
        "aes_key_encrypted": base64.b64encode(enc_aes_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "aes_key_length": 256,
    }

    #Devuelve el JSON
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decrypt_reserva(encrypted_json: bytes, rsa_private_pem: bytes, passphrase: bytes) -> bytes:
    """
    Descifra datos generados por encrypt_reserva().
      Descifra la clave AES con RSA privada.
      Usa AES-GCM para descifrar y verificar autenticidad.
    """
    #Cargamos el JSON con los datos cifrados
    try:
        payload = json.loads(encrypted_json.decode("utf-8"))
    except Exception as e:
        raise ValueError("JSON mal formado o corrupto") from e

    #Decodificamos los datos
    enc_aes_key = base64.b64decode(payload.get("aes_key_encrypted", ""))
    nonce = base64.b64decode(payload.get("nonce", ""))
    ciphertext = base64.b64decode(payload.get("ciphertext", ""))
    aad = base64.b64decode(payload.get("aad", ""))

    #Desciframos clave privada con la contraseña
    try:
        private_key = serialization.load_pem_private_key(
            rsa_private_pem,
            password=passphrase,
            backend=default_backend()
        )
    except Exception as e:
        raise ValueError("No se pudo cargar la clave privada (contraseña incorrecta o PEM inválido)") from e

    #Desciframps la clave AES
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

    #Desciframos el contenido con AES
    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception as e:
        raise ValueError("Error al descifrar el contenido AES-GCM") from e