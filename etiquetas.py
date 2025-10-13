import os
from cryptography.hazmat.primitives import hashes, hmac

#Clave secreta de 256 bits (32 bytes)
CLAVE = os.urandom(32)

def crear_hmac(mensaje: bytes) -> bytes:
    """
    Crea una etiqueta HMAC-SHA256 sobre 'mensaje'.
    'mensaje' DEBE ser bytes (si tienes str: usa .encode('utf-8'))
    """
    # Creamos el objeto HMAC con la clave y el algoritmo SHA-256
    # Combina la clave secreta con una funcion HASH para producir una eituqeta
    # unica
    h = hmac.HMAC(CLAVE, hashes.SHA256())
    # Se añade el contenido de la aplicacion y sus datos (en este caso
    # relacionada con los aviones) ademas este contenido sera el protegido
    h.update(mensaje)
    # Calcula el valor del codigo de autentificacion.Obtenemos la etiqueta (
    # tag) en una secuencia de bytes que representan la huella digital del
    # mensaje junto con la clave secreta
    tag = h.finalize()
    return tag

def verificar_hmac(mensaje: bytes, tag: bytes) -> bool:
    """
    Verifica que 'tag' corresponde al 'mensaje' con el mismo algoritmo.
    Devuelve True si es válido; False si falla.
    """
    #Se crea una nueva instancia de la clase HMAC utilizando la misma clave
    # y algoritmo (si el mensaje cambiara el resultado del HMAC tambien)
    h2 = hmac.HMAC(CLAVE, hashes.SHA256())
    #Carga el mensaje a verificar añadiendo el mensaje recibido al objeto HMAC
    h2.update(mensaje)
    #Aqui verificamos si los valores conciden entre el mensaje actual y la
    # etiqueta proprocionada y en caso contrario lanza una
    # excepcion
    try:
        h2.verify(tag)
        print("Verificación exitosa")
        return True
    except Exception:
        print("Verificación FALLÓ,el mensaje cambio")
        return False


