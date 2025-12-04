from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def firmar_mensaje(mensaje: bytes,rsa_private_pem: bytes,passphrase: bytes | None = None) -> bytes:
    """
    Genera una firma digital RSA del mensaje.
    """

    # Cargar clave privada desde el PEM
    private_key = serialization.load_pem_private_key(
        rsa_private_pem,
        password=passphrase,
        backend=default_backend()
    )

    # Crear firma del mensaje
    firma = private_key.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),   # MGF1 basado en SHA-256
            salt_length=padding.PSS.MAX_LENGTH  # Longitud de salt recomendada
        ),
        hashes.SHA256()                         # Hash usado en la firma
    )

    return firma


def verificar_firma_mensaje(mensaje: bytes,firma: bytes,public_pem: bytes) -> bool:
    """
    Se verifica que la firma corresponda al mensaje.
       - Si la firma coincide → el mensaje es auténtico y no ha sido modificado.
       - Si falla → se lanza una excepción, capturada y devuelta como False.
    """

    # Cargar clave pública desde el PEM
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )

    try:
        # Comprobar la firma usando los mismos parámetros utilizados al firmar
        public_key.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Firma válida

    except Exception:
        return False  # Firma incorrecta o no válida
