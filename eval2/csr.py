import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes


def generar_csr_usuario(nombre: str, private_key):
    """
    Genera un CSR (Certificate Signing Request) para el usuario.
    Este archivo se envía posteriormente a una Autoridad Certificadora (AC),
    que verificará la información y emitirá un certificado X.509.
    """

    # Ruta de la carpeta donde se guardarán los archivos del usuario
    user_dir = os.path.join("data/keys", nombre)

    # Datos de identidad que se incluirán en el CSR
    # Estos atributos aparecen luego en el certificado emitido por la AC.
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),                   # País
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),     # Provincia
        x509.NameAttribute(NameOID.LOCALITY_NAME, "MADRID"),              # Ciudad
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),            # Organización
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),                  # Nombre común
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"{nombre}@correo.com") # Email
    ])

    # Construcción del CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    # Convertir el CSR al formato PEM +
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Guardar el archivo usuario.csr en la carpeta del usuario
    with open(os.path.join(user_dir, "usuario.csr"), "wb") as f:
        f.write(csr_pem)
