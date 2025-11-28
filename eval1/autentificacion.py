import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from eval2.claves import generar_y_guardar_claves
from eval2.csr import generar_csr_usuario


# Ruta donde se almacenan los usuarios registrados junto a su salt y hash de contraseña
RUTA_USUARIOS = "data/usuarios.json"


def derivar_clave(contrasena: str, salt: bytes) -> bytes:
    """
    Deriva una clave segura usando Scrypt.
    - Scrypt es una KDF resistente a ataques de fuerza bruta y hardware especializado.
    - Recibe la contraseña del usuario y un salt único.
    - Devuelve un hash de 32 bytes que representa la contraseña derivada.
    """
    kdf = Scrypt(
        salt=salt,         # Salt aleatorio para evitar ataques de diccionario
        length=32,         # Tamaño del hash/clave resultante
        n=2**14,           # Coste computacional (más alto = más seguro)
        r=8,               # Parámetros internos del algoritmo
        p=1
    )
    return kdf.derive(contrasena.encode("utf-8"))


def verificar_clave(contrasena: str, salt: bytes, hash_guardado: bytes) -> bool:
    """
    Verifica que una contraseña introducida coincide con su hash guardado:
    - Se deriva nuevamente la clave con el mismo salt.
    - Si coincide con el hash almacenado → contraseña correcta.
    - Si no, Scrypt lanza InvalidKey.
    """
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
    """
    Registra un nuevo usuario en el sistema.
    """

    # HASH + SALT
    # Salt aleatorio para evitar ataques de rainbow tables
    salt = os.urandom(16)
    hash_generado = derivar_clave(contrasena, salt)

    # Cargar usuarios existentes si el archivo ya existe
    usuarios = {}
    if os.path.exists(RUTA_USUARIOS):
        with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
            usuarios = json.load(f)

    # Evitar que dos usuarios tengan el mismo nombre
    if nombre in usuarios:
        raise ValueError("El usuario ya existe")

    # Guardar los datos de hash y salt del usuario
    usuarios[nombre] = {
        "salt": salt.hex(),
        "hash": hash_generado.hex(),
    }

    # Guardar el archivo actualizado
    with open(RUTA_USUARIOS, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)

    # Se genera el par de claves RSA del usuario.
    # La clave privada se guarda cifrada con su contraseña
    private_key = generar_y_guardar_claves(nombre, contrasena)

    # GENERAR CSR
    # El CSR se usará para solicitar un certificado X.509 a la Autoridad Certificadora
    generar_csr_usuario(nombre, private_key)

    print(f"Usuario {nombre} registrado correctamente.")
    print(" - Claves generadas (private.pem / public.pem)")
    print(" - CSR generado correctamente (usuario.csr)")


def autenticar(nombre: str, contrasena: str) -> bool:
    """
    Verifica si un usuario puede autenticarse mediante su contraseña.
    """

    # Verifica si aún no existe el archivo de usuarios
    if not os.path.exists(RUTA_USUARIOS):
        print("No hay usuarios registrados aún")
        return False

    # Cargar todos los usuarios
    with open(RUTA_USUARIOS, "r", encoding="utf-8") as f:
        usuarios = json.load(f)

    # Verificar que el usuario exista
    if nombre not in usuarios:
        print("Usuario no encontrado.")
        return False

    # Obtener salt y hash del usuario
    salt = bytes.fromhex(usuarios[nombre]["salt"])
    hash_guardado = bytes.fromhex(usuarios[nombre]["hash"])

    # Comparar la contraseña introducida con la real
    if verificar_clave(contrasena, salt, hash_guardado):
        print("Los datos son correctos")
        return True
    else:
        print("Contraseña incorrecta.")
        return False
