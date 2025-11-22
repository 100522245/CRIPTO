import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from eval1.cifrado_descifrado import generate_rsa_keypair
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Archivo donde se guardan los usuarios, sus salt y hash de contraseña
RUTA_USUARIOS = "data/usuarios.json"


def derivar_clave(contrasena: str, salt: bytes) -> bytes:
    """Usamos Scrypt para derivar una clave de 32 bytes a partir de la
    contraseña y un salt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    return kdf.derive(contrasena.encode("utf-8"))


def verificar_clave(contrasena: str, salt: bytes, hash_guardado: bytes) -> bool:
    """Verificamos si el hash de la contraseña introducida coincide con el
    hash almacenado."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    try:
        kdf.verify(contrasena.encode("utf-8"), hash_guardado)
        return True
    except InvalidKey:
        return False


def registrar(nombre: str, contrasena: str):
    """Registra un usuario:
       - Genera un salt aleatorio y deriva el hash de la contraseña con Scrypt.
       - Genera par de claves RSA y las guarda en data/keys/<usuario>/.
       - Genera un CSR (Certificate Signing Request) para el usuario.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    # ===== 1) SALT + HASH DE CONTRASEÑA =====
    salt = os.urandom(16)
    hash_generado = derivar_clave(contrasena, salt)

    # Cargar usuarios existentes
    usuarios = {}
    if os.path.exists(RUTA_USUARIOS):
        with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)

    if nombre in usuarios:
        raise ValueError("El usuario ya existe")

    # Guardar hash + salt en JSON
    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
    }

    # ===== 2) CREAR CARPETA DEL USUARIO =====
    os.makedirs("data/keys", exist_ok=True)
    user_dir = os.path.join("data/keys", nombre)
    os.makedirs(user_dir, exist_ok=True)

    # ===== 3) GENERAR PAR DE CLAVES RSA =====
    private_key, public_key = generate_rsa_keypair()

    # Serializar clave privada cifrada con la contraseña
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            contrasena.encode("utf-8")
        )
    )

    # Serializar clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar claves en disco
    with open(os.path.join(user_dir, "private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(user_dir, "public.pem"), "wb") as f:
        f.write(public_pem)

    # Guardar usuarios.json actualizado
    with open(RUTA_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)

    # ===== 4) GENERAR CSR DEL USUARIO =====
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "MADRID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"{nombre}@correo.com"),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(os.path.join(user_dir, "usuario.csr"), "wb") as f:
        f.write(csr_pem)

    print(f"Usuario {nombre} registrado correctamente.")
    print(" - Claves generadas (private.pem / public.pem)")
    print(" - CSR generado correctamente (usuario.csr)")



def autenticar(nombre: str, contrasena: str) -> bool:
    """Comprueba usuario y contraseña."""
    if not os.path.exists(RUTA_USUARIOS):
        print("No hay usuarios registrados aún")
        return False

    # Cargamos los usuarios y verificamos que el nombre exista
    with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
        usuarios = json.load(f)
    if nombre not in usuarios:
        print("Usuario no encontrado.")
        return False

    # Recuperamos salt y hash para verificar la contraseña
    salt = bytes.fromhex(usuarios[nombre]["salt"])
    hash_guardado = bytes.fromhex(usuarios[nombre]["hash"])
    if verificar_clave(contrasena, salt, hash_guardado):
        print("Los datos son correctos")
        return True
    else:
        print("Contraseña incorrecta.")
        return False
