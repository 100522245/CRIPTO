from cifrado_descifrado import load_pem
private = load_pem("data/keys/12345/private.pem", b"12345")
public = load_pem("data/keys/12345/public.pem")
print("✅ Claves cargadas correctamente:", type(private), type(public))
