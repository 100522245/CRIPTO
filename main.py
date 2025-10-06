# main.py
from autentificacion import registrar_usuario, iniciar_sesion

# Registrar usuario nuevo
try:
    registrar_usuario("alice", "ContraseñaSegura2025!")
except ValueError as e:
    print(e)

# Probar login correcto
print("Login correcto:", iniciar_sesion("alice", "ContraseñaSegura2025!"))
# Probar login incorrecto
print("Login incorrecto:", iniciar_sesion("alice", "ErrorDeClave"))


