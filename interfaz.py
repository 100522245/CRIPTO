import os
import json
import tkinter as tk
from tkinter import messagebox

# --- Importar autenticación desde eval1 ---
from eval1 import autentificacion as auth
from eval1 import cifrado_descifrado as crypto
from eval1 import etiquetas as hmac_utils

# --- Rutas de datos ---
RUTA_VUELOS = "data/vuelos.json"
RUTA_RESERVAS = "data/reservados.json"


# ------------------ UTILIDADES JSON ------------------
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


# ------------------ LÓGICA DE VUELOS/RESERVAS ------------------
def vuelos_disponibles():
    """Lista de vuelos disponibles (cada vuelo es un dict)."""
    return _leer_json(RUTA_VUELOS, [])


def reservas_todas():
    """Lista de reservas (cada reserva es un dict)."""
    return _leer_json(RUTA_RESERVAS, [])


def vuelo_por_id(vuelo_id: str):
    """Devuelve el dict del vuelo por su número de vuelo."""
    for v in vuelos_disponibles():
        if str(v.get("numero_vuelo")) == vuelo_id:
            return v
    return None


def vuelo_esta_reservado(vuelo_id: str) -> bool:
    """True si ese vuelo ya está reservado."""
    return any(str(r.get("numero_vuelo")) == vuelo_id for r in reservas_todas())


def reservar_vuelo(vuelo_id: str, usuario: str):
    """Reserva el vuelo cifrado para el usuario."""
    vuelo = vuelo_por_id(vuelo_id)
    if not vuelo:
        return False, "Vuelo no encontrado"

    if vuelo_esta_reservado(vuelo_id):
        return False, "Vuelo ya reservado"

    # Guardar una versión cifrada de la reserva
    user_dir = os.path.join("data", "keys", usuario)
    public_path = os.path.join(user_dir, "public.pem")

    if not os.path.exists(public_path):
        return False, "No se encontró la clave pública del usuario"

    with open(public_path, "rb") as f:
        public_pem = f.read()

    reserva = {
        "usuario": usuario,
        "vuelo": vuelo
    }
    reserva_json = json.dumps(reserva, ensure_ascii=False).encode("utf-8")

    reserva_cifrada = crypto.encrypt_reserva(reserva_json, public_pem)
    tag = hmac_utils.crear_hmac(reserva_cifrada)

    os.makedirs("data/reservas", exist_ok=True)
    ruta_archivo = os.path.join("data/reservas", f"{usuario}_{vuelo_id}.json")
    with open(ruta_archivo, "wb") as f:
        f.write(reserva_cifrada)
    with open(ruta_archivo + ".tag", "wb") as f:
        f.write(tag)

    # Guardar registro plano
    reservas = reservas_todas()
    reservas.append({"usuario": usuario, **vuelo})
    _guardar_json(RUTA_RESERVAS, reservas)

    return True, f"Reserva guardada correctamente para el vuelo {vuelo_id}"


def reservas_de_usuario(usuario: str):
    """Filtra reservas por usuario (campo 'usuario')."""
    return [r for r in reservas_todas() if r.get("usuario") == usuario]


# ------------------ INTERFAZ TKINTER ------------------
class AppVuelos:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Gestión de Vuelos y Reservas")
        self.root.geometry("820x600")
        self.usuario_actual = None
        self.build_login()
        self.root.mainloop()

    # --------- VISTAS ---------
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

        self._refrescar_vuelos()

        # Botones de acción
        btns = tk.Frame(self.root)
        btns.pack(pady=8)
        tk.Button(btns, text="Reservar seleccionado", command=self.reservar_seleccionado).grid(row=0, column=0, padx=6)
        tk.Button(btns, text="Mis reservas", command=self.mostrar_mis_reservas).grid(row=0, column=1, padx=6)
        tk.Button(btns, text="Cerrar sesión", command=self.build_login).grid(row=0, column=2, padx=6)

        # Área de salida/mensajes
        self.output_text = tk.Text(self.root, height=14)
        self.output_text.pack(fill="both", expand=True, padx=10, pady=8)

    # --------- ACCIONES ---------
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

    def _refrescar_vuelos(self):
        """Recarga lista de vuelos en el ListBox."""
        self.listbox.delete(0, tk.END)
        vuelos = vuelos_disponibles()
        if not vuelos:
            self.listbox.insert(tk.END, "No hay vuelos cargados en data/vuelos.json")
            return

        for v in vuelos:
            numero = v.get("numero_vuelo")
            origen = v.get("lugar_origen", "")
            destino = v.get("lugar_destino", "")
            salida = v.get("hora_salida", "")
            llegada = v.get("hora_llegada", "")
            fecha = v.get("fecha", "")
            estado = " (RESERVADO)" if vuelo_esta_reservado(str(numero)) else ""
            self.listbox.insert(
                tk.END,
                f"{numero} | {origen} → {destino} | {fecha} {salida}-{llegada}{estado}"
            )

    def reservar_seleccionado(self):
        """Permite al usuario reservar el vuelo seleccionado."""
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("Reserva", "Selecciona un vuelo primero.")
            return
        linea = self.listbox.get(sel[0])
        numero_vuelo = linea.split("|")[0].strip()

        ok, msg = reservar_vuelo(numero_vuelo, self.usuario_actual)
        if ok:
            messagebox.showinfo("Reserva", msg)
            self._refrescar_vuelos()
            self.output_text.insert(tk.END, f"✅ {msg}\n")
        else:
            messagebox.showerror("Reserva", msg)

    def mostrar_mis_reservas(self):
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
                f"{r['hora_salida']}-{r['hora_llegada']}\n"
            )

    # --------- UTILIDAD ---------
    def clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()


# ------------------ PUNTO DE ENTRADA ------------------
if __name__ == "__main__":
    AppVuelos()
