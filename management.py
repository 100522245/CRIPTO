import os
import json
import pathlib
import random
import re

# Importamos funciones de otros módulos de nuestro proyecto
from eval2.certificado import cargar_certificado, obtener_clave_publica_usuario
from eval2.firma import firmar_mensaje, verificar_firma_mensaje
from eval2.claves import load_pem
from eval1.cifrado_descifrado import encrypt_reserva, decrypt_reserva
from eval1 import autentificacion 


# ────── CONSTANTES DE RUTAS ──────

# Archivo JSON que contiene la base de vuelos
RUTA_VUELOS = "data/vuelos.json"

# Directorio donde están las claves privadas de los pasajeros
RUTA_KEYS = "data/keys"

# Directorio donde se guardan las reservas cifradas
RUTA_RESERVAS = "data/reservas"

# Archivo que actúa como base de datos de usuarios
USUARIOS_DB = autentificacion.RUTA_USUARIOS


# ────── FUNCIONES UTILITARIAS JSON ──────

def _leer_json(ruta, por_defecto):
    """
    Lee un archivo JSON desde disco y devuelve su contenido.
    Si no existe o está corrupto, devuelve el valor por_defecto.
    """
    if not os.path.exists(ruta):
        return por_defecto
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return por_defecto


def _guardar_json(ruta, data):
    """
    Guarda un diccionario o lista como archivo JSON en disco.
    Crea la carpeta si no existe.
    """
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ────── FUNCIONES DE VUELOS ──────

def vuelos_disponibles():
    """
    Devuelve la lista completa de vuelos cargada desde el JSON.
    """
    return _leer_json(RUTA_VUELOS, [])


def vuelo_por_numero(numero_vuelo: str):
    """
    Busca y devuelve el vuelo cuyo número coincide con numero_vuelo.
    Devuelve None si no lo encuentra.
    """
    for v in vuelos_disponibles():
        if str(v.get("numero_vuelo")) == str(numero_vuelo):
            return v
    return None


# ────── FUNCIONES DE RESERVA ──────

def dir_reservas_usuario(usuario: str) -> str:
    """
    Devuelve el directorio donde se guardan las reservas de un usuario.
    Crea la carpeta si no existe.
    """
    ruta = os.path.join(RUTA_RESERVAS, usuario)
    os.makedirs(ruta, exist_ok=True)
    return ruta


def siguiente_indice_reserva(usuario: str) -> int:
    """
    Calcula el siguiente índice de reserva para un usuario.
    Los archivos se nombran como reserva1.json, reserva2.json, ...
    """
    ruta = dir_reservas_usuario(usuario)
    indices = []
    for nombre in os.listdir(ruta):
        # Buscar archivos que cumplan con el patrón "reservaN.json"
        m = re.match(r"reserva(\d+)\.json$", nombre)
        if m:
            indices.append(int(m.group(1)))
    # Si no hay reservas previas, comienza en 1
    return (max(indices) + 1) if indices else 1


def crear_reserva(usuario: str, numero_vuelo: str, passphrase: bytes):
    """
    Crea una reserva, la firma digitalmente con la clave privada del usuario
    y luego la cifra usando la clave pública del certificado del usuario.
    Guarda la reserva cifrada en data/reservas/<usuario>/reservaN.json.
    """

    # Obtener información del vuelo
    vuelo = vuelo_por_numero(numero_vuelo)
    if not vuelo:
        return False, "Vuelo no encontrado."

    # Ruta de la clave privada del usuario
    ruta_priv = os.path.join(RUTA_KEYS, usuario, "private.pem")
    if not os.path.exists(ruta_priv):
        return False, "No se encontró la clave privada del usuario."

    # Leer la clave privada desde disco
    with open(ruta_priv, "rb") as f:
        private_pem = f.read()

    # Crear información de reserva plana (sin cifrar)
    columnas = "ABCDEF"
    asiento = f"{random.randint(1, 40)}{random.choice(columnas)}"
    business = random.choice([True, False])

    reserva_plana = {
        "usuario": usuario,
        "numero_vuelo": numero_vuelo,
        "vuelo": vuelo,
        "asiento": asiento,
        "business": business,
        "hora_embarque": vuelo.get("hora_salida", "")
    }

    # Convertir a bytes JSON
    datos_bytes = json.dumps(reserva_plana, ensure_ascii=False).encode("utf-8")

    # Firmar la reserva usando la clave privada y la contraseña del usuario
    firma = firmar_mensaje(datos_bytes, private_pem, passphrase=passphrase)

    # Datos adicionales autenticados (AAD) para el cifrado híbrido
    aad = f"usuario={usuario}|vuelo={numero_vuelo}".encode("utf-8")

    try:
        cifrado_bytes = encrypt_reserva(datos_bytes, usuario, aad=aad, firma=firma)
    except Exception as e:
        return False, f"Error al cifrar la reserva: {e}"

    # Guardar la reserva cifrada en disco
    user_dir = dir_reservas_usuario(usuario)
    indice = siguiente_indice_reserva(usuario)
    ruta_out = os.path.join(user_dir, f"reserva{indice}.json")

    with open(ruta_out, "wb") as f:
        f.write(cifrado_bytes)

    return True, "Reserva realizada correctamente (cifrada y firmada con certificado)."


# ────── FUNCIONES DE DESCIFRADO DE RESERVA ──────

def cargar_reservas_descifradas(usuario: str, passphrase: bytes):
    """
    Descifra todas las reservas de un usuario usando su clave privada,
    y verifica las firmas usando la clave pública del certificado.
    Devuelve una lista de diccionarios con la información de cada reserva,
    incluyendo campos auxiliares:
      _tiene_firma: True si la reserva estaba firmada
      _firma_valida: True si la firma es correcta
    """

    if passphrase is None:
        raise ValueError("Se requiere la contraseña para descifrar las reservas.")

    # Leer la clave privada del usuario
    ruta_priv = os.path.join(RUTA_KEYS, usuario, "private.pem")
    if not os.path.exists(ruta_priv):
        raise FileNotFoundError("Falta la clave privada del usuario.")

    with open(ruta_priv, "rb") as f:
        private_pem = f.read()

    # Obtener la clave pública certificada del usuario
    public_pem = obtener_clave_publica_usuario(usuario)

    # Carpeta con las reservas cifradas del usuario
    carpeta = dir_reservas_usuario(usuario)
    reservas = []

    for archivo in os.listdir(carpeta):
        # Solo procesar archivos con formato "reservaN.json"
        if not (archivo.startswith("reserva") and archivo.endswith(".json")):
            continue

        ruta = os.path.join(carpeta, archivo)
        with open(ruta, "rb") as f:
            cifrado = f.read()

        # Descifrar la reserva (AES + RSA)
        plano_bytes, firma = decrypt_reserva(cifrado, private_pem, passphrase)

        # Convertir JSON a diccionario Python
        reserva = json.loads(plano_bytes.decode("utf-8"))

        # Verificar la firma si existe
        firma_valida = False
        if firma:
            firma_valida = verificar_firma_mensaje(plano_bytes, firma, public_pem)

        # Añadir campos auxiliares sobre la firma
        reserva["_tiene_firma"] = firma is not None
        reserva["_firma_valida"] = firma_valida

        reservas.append(reserva)

    return reservas
