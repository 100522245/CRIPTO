# interfaz_vuelos.py
"""
Interfaz:
- Registro / Login (registro extendido con nombre/email/fecha)
- Listado de vuelos (esencial)
- Reservar (crea archivo cifrado + registro resumido en reservados.json)
- Ver "Mis reservas" (resumen) — sin opción de descifrar desde la UI
- ✨ Sin tercer cuadro de salida (eliminado)
"""

import os
import json
import random
import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Importa tus módulos (ajusta 'eval1' si tu estructura es distinta)
from eval1 import autentificacion as auth
from eval1 import cifrado_descifrado as crypto  # se sigue usando al reservar (cifrado)

# Rutas
RUTA_VUELOS = "data/vuelos.json"
RUTA_RESERVAS = "data/reservados.json"       # fichero resumido visible (lista de reservas)
RUTA_KEYS = "data/keys"                      # espera data/keys/<usuario>/{public.pem,private.pem}
RUTA_RESERVAS_CIF = "data/reservas"          # archivos cifrados <usuario>_<numero_vuelo>.json

# Ruta fichero usuarios (usa la definida en auth si existe)
USUARIOS_DB = getattr(auth, "RUTA_USUARIOS", getattr(auth, "DB_PATH", "data/usuarios.json"))


# ------------------- UTILIDADES JSON -------------------
def _leer_json(ruta, por_defecto):
    if not os.path.exists(ruta):
        return por_defecto
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return por_defecto


def _guardar_json(ruta, data):
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ------------------- FUNCIONES DE DOMINIO -------------------
def vuelos_disponibles():
    """Devuelve lista de vuelos (cada vuelo es dict)."""
    return _leer_json(RUTA_VUELOS, [])


def reservas_todas():
    """Devuelve lista de reservas resumidas."""
    return _leer_json(RUTA_RESERVAS, [])


def reservas_de_usuario(usuario: str):
    """Filtra reservas resumidas por usuario."""
    return [r for r in reservas_todas() if str(r.get("usuario")) == str(usuario)]


def vuelo_por_numero(numero_vuelo: str):
    for v in vuelos_disponibles():
        if str(v.get("numero_vuelo")) == str(numero_vuelo):
            return v
    return None


def ruta_public_key(usuario: str) -> str:
    return os.path.join(RUTA_KEYS, usuario, "public.pem")


def ruta_reserva_cifrada(usuario: str, numero_vuelo: str) -> str:
    os.makedirs(RUTA_RESERVAS_CIF, exist_ok=True)
    filename = f"{usuario}_{numero_vuelo}.json"
    return os.path.join(RUTA_RESERVAS_CIF, filename)


# ---------- Asignación simple de asiento (evita duplicados por vuelo) ----------
def _siguiente_asiento_libre(numero_vuelo: str) -> str:
    """
    Asigna asiento: filas 1..40, columnas A..F.
    Evita duplicados consultando 'reservados.json' (resumen).
    """
    ocupados = {
        r.get("asiento")
        for r in reservas_todas()
        if str(r.get("numero_vuelo")) == str(numero_vuelo)
    }
    columnas = "ABCDEF"
    for fila in range(1, 41):
        for col in columnas:
            seat = f"{fila}{col}"
            if seat not in ocupados:
                return seat
    return "NA"


# ------------------- RESERVAR (crea cifrado y registro resumido) -------------------
def reservar_vuelo(numero_vuelo: str, usuario: str):
    """
    1) Cifra la reserva completa con crypto.encrypt_reserva(...).
    2) Guarda archivo cifrado en data/reservas/<usuario>_<numero_vuelo>.json.
    3) Añade entrada resumida en data/reservados.json con:
       { "usuario", "numero_vuelo", "asiento", "business", "hora_embarque" }
    """
    vuelo = vuelo_por_numero(numero_vuelo)
    if not vuelo:
        return False, "Vuelo no encontrado."

    # Evitar doble reserva del mismo vuelo (simplificado)
    if any(str(r.get("numero_vuelo")) == str(numero_vuelo) for r in reservas_todas()):
        return False, "El vuelo ya está reservado."

    # Comprobar clave pública del usuario (necesaria para cifrado híbrido)
    pub_path = ruta_public_key(usuario)
    if not os.path.exists(pub_path):
        return False, f"No se encontró la clave pública del usuario: {pub_path}"

    with open(pub_path, "rb") as f:
        public_pem = f.read()

    # Asignar asiento y business (aleatorio)
    asiento = _siguiente_asiento_libre(numero_vuelo)
    business = random.choice([True, False])
    hora_embarque = vuelo.get("hora_salida", "")

    # Construimos la reserva en claro (esto será cifrado)
    reserva_plana = {
        "usuario": usuario,
        "asiento": asiento,
        "business": business,
        "vuelo": vuelo  # todo el dict de vuelo con origen/destino/horas/fecha
    }
    reserva_bytes = json.dumps(reserva_plana, ensure_ascii=False).encode("utf-8")

    # Cifrado autenticado (AES-GCM) + encapsulado de clave AES con RSA-OAEP
    aad = f"usuario={usuario}|vuelo={numero_vuelo}".encode("utf-8")
    reserva_cifrada = crypto.encrypt_reserva(reserva_bytes, public_pem, aad=aad)

    # Guardamos el fichero cifrado
    ruta_cif = ruta_reserva_cifrada(usuario, numero_vuelo)
    with open(ruta_cif, "wb") as f:
        f.write(reserva_cifrada)

    # Guardamos resumen en reservados.json (solo lo esencial + numero_vuelo para enlace interno)
    resumen = {
        "usuario": usuario,
        "numero_vuelo": numero_vuelo,
        "asiento": asiento,
        "business": business,
        "hora_embarque": hora_embarque
    }
    reservas = reservas_todas()
    reservas.append(resumen)
    _guardar_json(RUTA_RESERVAS, reservas)

    return True, f"Reserva creada (vuelo {numero_vuelo}, asiento {asiento}, business={business})"


# ------------------- INTERFAZ TKINTER -------------------
class AppVuelos:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Gestión Vuelos / Reservas (AES-GCM + RSA-OAEP)")
        self.root.geometry("900x600")
        self.root.minsize(820, 520)
        self.usuario_actual = None

        # Estilos bonitos con ttk
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("Header.TLabelframe.Label", font=("Segoe UI", 11, "bold"))
        self.style.configure("TButton", font=("Segoe UI", 10), padding=6)
        self.style.configure("TLabelframe", padding=10)
        self.root.configure(bg="#f3f4f6")

        # Widgets que usaremos
        self.listbox_vuelos = None
        self.listbox_reservas = None

        self.build_login()
        self.root.mainloop()

    # ------------- Login / Registro extendido -------------
    def build_login(self):
        self.clear_root()

        container = ttk.Frame(self.root, padding=20)
        container.pack(expand=True)

        ttk.Label(container, text="Iniciar sesión", style="Title.TLabel").pack(pady=(0, 10))

        form = ttk.Frame(container)
        form.pack()

        ttk.Label(form, text="Usuario:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.usuario_entry = ttk.Entry(form, width=28)
        self.usuario_entry.grid(row=0, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(form, text="Contraseña:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.pass_entry = ttk.Entry(form, show="*", width=28)
        self.pass_entry.grid(row=1, column=1, sticky="w", padx=6, pady=6)

        btns = ttk.Frame(container)
        btns.pack(pady=12)
        ttk.Button(btns, text="Iniciar sesión", command=self.login).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Registrar (nuevo)", command=self.build_register_form).grid(row=0, column=1, padx=6)

    def build_register_form(self):
        """Formulario de registro extendido (usuario, contraseña, nombre, email, fecha_nac)."""
        self.clear_root()

        container = ttk.Frame(self.root, padding=20)
        container.pack(expand=True, fill="both")

        ttk.Label(container, text="Registro de usuario", style="Title.TLabel").pack(pady=10)

        form = ttk.Frame(container)
        form.pack(pady=6)

        labels = [
            ("Usuario (login):", "usuario"),
            ("Contraseña:", "password"),
            ("Nombre completo:", "nombre"),
            ("Correo electrónico:", "email"),
            ("Fecha de nacimiento (YYYY-MM-DD):", "fecha_nac"),
        ]
        self.reg_entries = {}
        for i, (texto, clave) in enumerate(labels):
            ttk.Label(form, text=texto).grid(row=i, column=0, sticky="e", padx=6, pady=4)
            show = "*" if clave == "password" else None
            e = ttk.Entry(form, show=show, width=32)
            e.grid(row=i, column=1, sticky="w", padx=6, pady=4)
            self.reg_entries[clave] = e

        btns = ttk.Frame(container)
        btns.pack(pady=12)
        ttk.Button(btns, text="Crear cuenta", command=self.registrar_extendido).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Volver", command=self.build_login).grid(row=0, column=1, padx=6)

    def registrar_extendido(self):
        """Registra credenciales con auth.registrar() y añade metadatos al JSON de usuarios."""
        usuario = self.reg_entries["usuario"].get().strip()
        password = self.reg_entries["password"].get()
        nombre = self.reg_entries["nombre"].get().strip()
        email = self.reg_entries["email"].get().strip()
        fecha_nac = self.reg_entries["fecha_nac"].get().strip()

        # Validaciones básicas
        if not usuario or not password:
            messagebox.showwarning("Registro", "Usuario y contraseña obligatorios.")
            return
        if not nombre:
            messagebox.showwarning("Registro", "Introduce tu nombre.")
            return
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            messagebox.showwarning("Registro", "Email no válido.")
            return
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", fecha_nac):
            messagebox.showwarning("Registro", "Fecha con formato YYYY-MM-DD.")
            return

        # 1) Registrar credenciales (Scrypt, generación de claves RSA, etc.)
        try:
            auth.registrar(usuario, password)
        except Exception as e:
            messagebox.showerror("Registro", f"Error al registrar: {e}")
            return

        # 2) Añadir metadatos al JSON de usuarios (sin tocar salt/hash)
        usuarios = _leer_json(USUARIOS_DB, {})
        perfil = usuarios.get(usuario, {})
        perfil.update({
            "nombre": nombre,
            "email": email,
            "fecha_nacimiento": fecha_nac
        })
        usuarios[usuario] = perfil
        _guardar_json(USUARIOS_DB, usuarios)

        messagebox.showinfo("Registro", "Cuenta creada correctamente. Se han generado tus claves RSA.")
        self.build_login()

    # ------------- Panel principal (vuelos + reservas) -------------
    def build_panel(self):
        self.clear_root()

        header = ttk.Frame(self.root, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(header, text=f"Usuario: {self.usuario_actual}", style="Title.TLabel").pack(side="left")

        # Marco superior: Vuelos disponibles (esencial)
        marco_sup = ttk.Labelframe(self.root, text="Vuelos disponibles (esencial)", style="Header.TLabelframe")
        marco_sup.pack(fill="both", expand=True, padx=12, pady=(6, 4))

        frame_sup = ttk.Frame(marco_sup)
        frame_sup.pack(fill="both", expand=True)

        sb1 = ttk.Scrollbar(frame_sup)
        sb1.pack(side="right", fill="y")

        self.listbox_vuelos = tk.Listbox(frame_sup, height=10, yscrollcommand=sb1.set, selectmode=tk.SINGLE, font=("Segoe UI", 10))
        self.listbox_vuelos.pack(side="left", fill="both", expand=True)
        sb1.config(command=self.listbox_vuelos.yview)

        btns_sup = ttk.Frame(marco_sup)
        btns_sup.pack(pady=8)
        ttk.Button(btns_sup, text="Reservar seleccionado", command=self.reservar_seleccionado).grid(row=0, column=0, padx=6)
        ttk.Button(btns_sup, text="Refrescar", command=self.refrescar_listas).grid(row=0, column=1, padx=6)

        # Marco inferior: Mis reservas (resumen)
        marco_inf = ttk.Labelframe(self.root, text="Mis reservas (resumen)", style="Header.TLabelframe")
        marco_inf.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        frame_inf = ttk.Frame(marco_inf)
        frame_inf.pack(fill="both", expand=True)

        sb2 = ttk.Scrollbar(frame_inf)
        sb2.pack(side="right", fill="y")

        self.listbox_reservas = tk.Listbox(frame_inf, height=10, yscrollcommand=sb2.set, selectmode=tk.SINGLE, font=("Segoe UI", 10))
        self.listbox_reservas.pack(side="left", fill="both", expand=True)
        sb2.config(command=self.listbox_reservas.yview)

        btns_inf = ttk.Frame(marco_inf)
        btns_inf.pack(pady=8)
        ttk.Button(btns_inf, text="Cerrar sesión", command=self.logout).grid(row=0, column=0, padx=6)

        # Carga inicial
        self.refrescar_listas()

    # ------------- Acciones de Login/Registro/Vuelos -------------
    def login(self):
        if auth.autenticar(self.usuario_entry.get(), self.pass_entry.get()):
            self.usuario_actual = self.usuario_entry.get()
            self.build_panel()
        else:
            messagebox.showerror("Login", "Usuario o contraseña incorrectos.")

    def logout(self):
        self.usuario_actual = None
        self.build_login()

    def refrescar_listas(self):
        # Vuelos (arriba): "numero | fecha · hora_salida | origen → destino"
        self.listbox_vuelos.delete(0, tk.END)
        vuelos = vuelos_disponibles()
        if not vuelos:
            self.listbox_vuelos.insert(tk.END, "No hay vuelos en data/vuelos.json")
        else:
            for v in vuelos:
                num = v.get("numero_vuelo", "N/A")
                fecha = v.get("fecha", "")
                hs = v.get("hora_salida", "")
                o = v.get("lugar_origen", "")
                d = v.get("lugar_destino", "")
                estado = " (RESERVADO)" if any(str(r.get("numero_vuelo")) == str(num) for r in reservas_todas()) else ""
                self.listbox_vuelos.insert(tk.END, f"{num} | {fecha} · {hs} | {o} → {d}{estado}")

        # Mis reservas (abajo): "num | fecha · salida-llegada (embarque) | origen→destino | asiento | Business"
        self.listbox_reservas.delete(0, tk.END)
        mis = reservas_de_usuario(self.usuario_actual)
        if not mis:
            self.listbox_reservas.insert(tk.END, "No tienes reservas.")
        else:
            for r in mis:
                num = r.get("numero_vuelo", "N/A")
                fecha = r.get("fecha", "")
                hora_emb = r.get("hora_embarque", "")
                v = vuelo_por_numero(num) or {}
                o = v.get("lugar_origen", "")
                d = v.get("lugar_destino", "")
                hs = v.get("hora_salida", "")
                hl = v.get("hora_llegada", "")
                asiento = r.get("asiento", "-")
                biz = "Sí" if r.get("business") else "No"
                if not fecha:
                    fecha = v.get("fecha", "")
                self.listbox_reservas.insert(
                    tk.END,
                    f"{num} | {fecha} · {hs}-{hl} (embarque {hora_emb}) | {o} → {d} | asiento: {asiento} | Business: {biz}"
                )

    def reservar_seleccionado(self):
        sel = self.listbox_vuelos.curselection()
        if not sel:
            messagebox.showwarning("Reserva", "Selecciona un vuelo primero.")
            return
        linea = self.listbox_vuelos.get(sel[0])
        numero_vuelo = linea.split("|")[0].strip()

        ok, msg = reservar_vuelo(numero_vuelo, self.usuario_actual)
        if ok:
            messagebox.showinfo("Reserva", msg)
            self.refrescar_listas()
        else:
            messagebox.showerror("Reserva", msg)

    # ------------- UTILIDADES UI -------------
    def clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()


# ------------- ENTRYPOINT -------------
if __name__ == "__main__":
    AppVuelos()
