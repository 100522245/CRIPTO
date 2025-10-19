# interfaz_vuelos.py
import os
import json
import tkinter as tk
from tkinter import messagebox

# --- Tus módulos existentes ---
from eval1 import autentificacion as auth

# Si más adelante reactivas cifrado/HMAC:
# import cifrado_descifrado as crypto
# import etiquetas as hmac_utils

# Rutas de datos
RUTA_VUELOS = "data/vuelos.json"
RUTA_RESERVAS = "data/reservados.json"


# ------------------ Utilidades JSON ------------------
def _leer_json(ruta, por_defecto):
    """Carga un JSON o devuelve 'por_defecto' si no existe o está corrupto."""
    if not os.path.exists(ruta):
        return por_defecto
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return por_defecto


def _guardar_json(ruta, data):
    """Guarda un JSON con indentación y crea la carpeta si hace falta."""
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ------------------ Lógica de vuelos/reservas ------------------
def vuelos_disponibles():
    """Lista de vuelos disponibles (cada vuelo es un dict)."""
    return _leer_json(RUTA_VUELOS, [])


def reservas_todas():
    """Lista de reservas (cada reserva es un dict)."""
    return _leer_json(RUTA_RESERVAS, [])


def vuelo_por_numero(numero_vuelo: str):
    """Devuelve el dict del vuelo por su número, o None si no existe."""
    for v in vuelos_disponibles():
        if v.get("numero_vuelo") == numero_vuelo:
            return v
    return None


def vuelo_esta_reservado(numero_vuelo: str) -> bool:
    """True si ese número de vuelo ya está en reservados.json."""
    return any(r.get("numero_vuelo") == numero_vuelo for r in reservas_todas())


def reservar_vuelo(numero_vuelo: str, usuario: str) -> bool:
    """
    Crea la reserva copiando TODOS los campos del vuelo y añade:
    - nombre_pasajero = usuario (no se pide aparte)
    - usuario (quién reservó)
    Devuelve True si se pudo reservar; False si ya estaba reservado o no existe.
    """
    if vuelo_esta_reservado(numero_vuelo):
        return False
    vuelo = vuelo_por_numero(numero_vuelo)
    if not vuelo:
        return False

    reserva = {
        **vuelo,  # incluye numero_vuelo, lugar_origen, lugar_destino, hora_salida, hora_llegada, fecha
        "nombre_pasajero": usuario,
        "usuario": usuario
    }
    reservas = reservas_todas()
    reservas.append(reserva)
    _guardar_json(RUTA_RESERVAS, reservas)
    return True


def reservas_de_usuario(usuario: str):
    """Filtra reservas por usuario (campo 'usuario')."""
    return [r for r in reservas_todas() if r.get("usuario") == usuario]


# ------------------ Interfaz Tkinter ------------------
class AppVuelos:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Compra y Reserva de Vuelos")
        self.root.geometry("780x580")
        self.usuario_actual = None
        self.build_login()
        self.root.mainloop()

    # --------- Vistas ---------
    def build_login(self):
        """Pantalla de inicio de sesión y registro."""
        self.clear_root()
        tk.Label(self.root, text="Usuario:", font=("Segoe UI", 10)).pack(pady=(16, 2))
        self.usuario_entry = tk.Entry(self.root)
        self.usuario_entry.pack()
        tk.Label(self.root, text="Contraseña:", font=("Segoe UI", 10)).pack(pady=(8, 2))
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack()
        btns = tk.Frame(self.root)
        btns.pack(pady=12)
        tk.Button(btns, text="Registrar", command=self.registrar).grid(row=0, column=0, padx=6)
        tk.Button(btns, text="Iniciar sesión", command=self.login).grid(row=0, column=1, padx=6)

    def build_vuelos(self):
        """Vista principal tras login: lista, reservar, ver 'Mis vuelos'."""
        self.clear_root()
        tk.Label(self.root, text=f"Usuario: {self.usuario_actual}",
                 font=("Segoe UI", 11, "bold")).pack(pady=6)

        # Listbox de vuelos
        frame = tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=6)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side="right", fill="y")

        self.listbox = tk.Listbox(frame, height=12, yscrollcommand=scrollbar.set, selectmode=tk.SINGLE)
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)

        self._refrescar_lista_vuelos()

        # Botones de acción
        btns = tk.Frame(self.root)
        btns.pack(pady=8)
        tk.Button(btns, text="Reservar seleccionado", command=self.reservar_seleccionado).grid(row=0, column=0, padx=6)
        tk.Button(btns, text="Mis vuelos", command=self.mostrar_mis_vuelos).grid(row=0, column=1, padx=6)
        tk.Button(btns, text="Cerrar sesión", command=self.build_login).grid(row=0, column=2, padx=6)

        # Área de salida/mensajes
        self.output_text = tk.Text(self.root, height=14)
        self.output_text.pack(fill="both", expand=True, padx=10, pady=8)

    # --------- Acciones ---------
    def registrar(self):
        """Registrar un nuevo usuario."""
        try:
            auth.registrar(self.usuario_entry.get(), self.pass_entry.get())
            messagebox.showinfo("Registro", "Usuario registrado correctamente.")
        except Exception as e:
            messagebox.showerror("Registro", str(e))

    def login(self):
        """Autenticar usuario existente."""
        if auth.autenticar(self.usuario_entry.get(), self.pass_entry.get()):
            self.usuario_actual = self.usuario_entry.get()
            self.build_vuelos()
        else:
            messagebox.showerror("Login", "Usuario o contraseña incorrectos.")

    def _refrescar_lista_vuelos(self):
        """
        Rellena la lista con:
        'numero | fecha | origen→destino | salida-llegada (RESERVADO?)'
        """
        self.listbox.delete(0, tk.END)
        vuelos = vuelos_disponibles()
        if not vuelos:
            self.listbox.insert(tk.END, "No hay vuelos cargados en data/vuelos.json")
            return
        for v in vuelos:
            num = v.get("numero_vuelo", "N/A")
            fecha = v.get("fecha", "")
            o = v.get("lugar_origen", "")
            d = v.get("lugar_destino", "")
            hs = v.get("hora_salida", "")
            hl = v.get("hora_llegada", "")
            estado = " (RESERVADO)" if vuelo_esta_reservado(num) else ""
            self.listbox.insert(tk.END, f"{num} | {fecha} | {o}→{d} | {hs}-{hl}{estado}")

    def reservar_seleccionado(self):
        """Permite al usuario reservar el vuelo seleccionado."""
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("Reserva", "Selecciona un vuelo primero.")
            return
        linea = self.listbox.get(sel[0])
        numero_vuelo = linea.split("|")[0].strip()

        if vuelo_esta_reservado(numero_vuelo):
            messagebox.showerror("Reserva", f"El vuelo {numero_vuelo} ya está reservado.")
            return

        # No pedimos nombre del pasajero: se usa el usuario logueado
        ok = reservar_vuelo(numero_vuelo, self.usuario_actual)
        if ok:
            messagebox.showinfo("Reserva", f"Reserva realizada para {numero_vuelo}.")
            self._refrescar_lista_vuelos()
            self.output_text.insert(
                tk.END,
                f"✅ Reservado {numero_vuelo} por {self.usuario_actual}\n"
            )
        else:
            messagebox.showerror("Reserva", "No se pudo reservar (vuelo inexistente o ya reservado).")

    def mostrar_mis_vuelos(self):
        """Muestra las reservas del usuario actual."""
        mis = reservas_de_usuario(self.usuario_actual)
        self.output_text.delete("1.0", tk.END)
        if not mis:
            self.output_text.insert(tk.END, "No tienes reservas.\n")
            return
        self.output_text.insert(tk.END, f"🧾 Reservas de {self.usuario_actual}:\n")
        for r in mis:
            self.output_text.insert(
                tk.END,
                f"- {r['numero_vuelo']} | {r.get('fecha','')} | {r['lugar_origen']}→{r['lugar_destino']} | "
                f"{r['hora_salida']}-{r['hora_llegada']} | pasajero: {r['nombre_pasajero']}\n"
            )

    # --------- Utilidad ---------
    def clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()


# Punto de entrada
if __name__ == "__main__":
    AppVuelos()
