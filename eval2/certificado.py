import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization

RUTA_CA_CERT = "AC1/ac1cert.pem"


def cargar_certificado(path: str):
    """Carga un certificado X.509 desde un archivo PEM."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"No existe el certificado: {path}")

    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def obtener_clave_publica_usuario(usuario: str):
    """
    Carga el certificado del usuario, valida que ha sido emitido por la CA
    y devuelve la clave pública en formato PEM.
    """
    ruta_cert_usuario = f"data/keys/{usuario}/cert.pem"

    cert_usuario = cargar_certificado(ruta_cert_usuario)
    cert_ca = cargar_certificado(RUTA_CA_CERT)

    # Verificar que la CA emitió ese certificado
    try:
        cert_usuario.verify_directly_issued_by(cert_ca)
    except Exception as e:
        raise ValueError(f"El certificado del usuario NO es válido o no fue emitido por la CA: {e}")

    # Extraer clave pública como PEM
    public_key = cert_usuario.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
