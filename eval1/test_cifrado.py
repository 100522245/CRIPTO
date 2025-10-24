import os
import json
from eval1 import cifrado_descifrado as crypto
from eval1 import autentificacion as auth

# --- DATOS DE PRUEBA ---
usuario = "ivan900"
password = "1234"  # Usa la misma con la que registraste

mensaje_original = {
    "usuario": usuario,
    "numero_vuelo": "IB1001",
    "lugar_origen": "Madrid",
    "lugar_destino": "Barcelona",
    "fecha": "2025-11-01"
}

print("🔹 Mensaje original:")
print(json.dumps(mensaje_original, indent=4, ensure_ascii=False))

# --- RUTAS DE CLAVES ---
private_path = os.path.join("data", "keys", usuario, "private.pem")
public_path = os.path.join("data", "keys", usuario, "public.pem")

# --- LEER CLAVES RSA ---
with open(public_path, "rb") as f:
    public_pem = f.read()

with open(private_path, "rb") as f:
    private_pem = f.read()

# --- CIFRAR ---
mensaje_bytes = json.dumps(mensaje_original, ensure_ascii=False).encode("utf-8")
cifrado = crypto.encrypt_reserva(mensaje_bytes, public_pem)
print("\n🔒 Texto cifrado (JSON codificado):")
print(cifrado.decode("utf-8"))

# --- DESCIFRAR ---
descifrado_bytes = crypto.decrypt_reserva(cifrado, private_pem, password.encode("utf-8"))
mensaje_descifrado = json.loads(descifrado_bytes.decode("utf-8"))

print("\n🔓 Mensaje descifrado:")
print(json.dumps(mensaje_descifrado, indent=4, ensure_ascii=False))

# --- COMPROBAR ---
if mensaje_original == mensaje_descifrado:
    print("\n✅ Cifrado y descifrado correctos.")
else:
    print("\n❌ Los datos no coinciden, hay un error en el proceso.")
