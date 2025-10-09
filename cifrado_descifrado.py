from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64

def cifrar_AES(mensaje: str):
    """
    Cifra un mensaje usando AES en modo CBC (simétrico).
    """
    # Generamos una clave segura de 256 bits (32 bytes)
    clave = os.urandom(32)
    iv = os.urandom(16)  # vector de inicialización (16 bytes)

    # Añadimos padding para que el texto sea múltiplo del tamaño del bloque
    padder = padding.PKCS7(128).padder()
    texto_padded = padder.update(mensaje.encode('utf-8')) + padder.finalize()

    # Creamos el cifrador
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(texto_padded) + encryptor.finalize()

    # Mostramos información de depuración
    print("=== CIFRADO AES ===")
    print(f"🔐 Algoritmo: AES (Simétrico)")
    print(f"🔑 Longitud de clave: {len(clave) * 8} bits")
    print(f"🧾 Clave (hex): {clave.hex()}")
    print(f"🧮 IV (hex): {iv.hex()}")
    print(f"📤 Texto cifrado (Base64): {base64.b64encode(cifrado).decode('utf-8')}")
    print()

    return cifrado, clave, iv


def descifrar_AES(cifrado: bytes, clave: bytes, iv: bytes):
    """
    Descifra un mensaje cifrado con AES en modo CBC.
    """
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
    decryptor = cipher.decryptor()
    texto_padded = decryptor.update(cifrado) + decryptor.finalize()

    # Quitamos el padding
    unpadder = padding.PKCS7(128).unpadder()
    texto = unpadder.update(texto_padded) + unpadder.finalize()

    print("=== DESCIFRADO AES ===")
    print(f"📥 Texto descifrado: {texto.decode('utf-8')}")
    print()

    return texto.decode('utf-8')


if __name__ == "__main__":
    # ===== CIFRADO SIMÉTRICO =====
    mensaje = "Hola, este es un mensaje confidencial."
    cifrado, clave, iv = cifrar_AES(mensaje)
    descifrar_AES(cifrado, clave, iv)

