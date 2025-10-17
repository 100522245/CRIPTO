import os, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#Generar o cargar RSA keys
def generate_rsa_keys(password: bytes):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serializar clave privada cifrada (PEM)
    enc_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    # Serializar clave pública (PEM)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return enc_private_pem, public_pem


#Cifrar datos con AES-GCM
def encrypt_message(data: bytes, aad: bytes, rsa_public_pem: bytes):
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, data, aad)

    # Cifrar la clave AES con la clave pública RSA
    public_key = serialization.load_pem_public_key(rsa_public_pem)
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Empaquetar en JSON (seguro y portable)
    payload = {
        "algorithm": "AES-GCM + RSA-OAEP",
        "aes_key_encrypted": base64.b64encode(enc_aes_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aad": base64.b64encode(aad).decode(),
        "key_length": 128
    }

    return json.dumps(payload, indent=4).encode()


#Descifrar mensaje
def decrypt_message(encrypted_json: bytes, rsa_private_pem: bytes, password: bytes):
    payload = json.loads(encrypted_json.decode())

    private_key = serialization.load_pem_private_key(
        rsa_private_pem, password=password
    )

    enc_aes_key = base64.b64decode(payload["aes_key_encrypted"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    aad = base64.b64decode(payload["aad"])

    # Descifrar clave AES con RSA
    aes_key = private_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descifrar datos con AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext


#DEMO (JSON de vuelo)
if __name__ == "__main__":
    password = b"clave_segura_usuario"
    enc_priv, pub = generate_rsa_keys(password)

    # 🛫 Datos del vuelo (en JSON)
    flight_data = {
        "numero_vuelo": "IB3478",
        "nombre_pasajero": "Carlos Perez",
        "lugar_destino": "Madrid",
        "lugar_llegada": "Paris",
        "hora_salida": "2025-10-20T09:45",
        "hora_llegada": "2025-10-20T11:30"
    }

    # Convertimos el JSON a bytes para cifrar
    data_bytes = json.dumps(flight_data, indent=4).encode()
    aad = b"informacion de vuelo autenticada"

    encrypted_json = encrypt_message(data_bytes, aad, pub)
    print("\n🧩 Datos cifrados:")
    print(encrypted_json.decode())

    decrypted = decrypt_message(encrypted_json, enc_priv, password)
    print("\n✅ Datos descifrados (JSON original):")
    print(decrypted.decode())