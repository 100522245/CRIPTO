import os
import json
import random
import re
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

from eval1 import autentificacion as auth
import management  # <-- Importamos nuestro management.py

# ---------------------------------------------------------------------------
# INTERFAZ TKINTER
# ---------------------------------------------------------------------------
class AppVuelos:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Gestión de vuelos y reservas")
        self.root.geometry("900x600")
        self.root.minsize(820, 520)

        self.usuario_actual: str | None = None
        self.password_actual: str | None = None  # para descifrar la clave privada

        self._configurar_estilo()
        self.build_login()

        self.root.mainloop()

    def _configurar_estilo(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("TLabelframe.Label", font=("Segoe UI", 11, "bold"))

    # ---------------- LOGIN ----------------
    def build_login(self):
        self._clear_root()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)

        ttk.Label(frame, text="Iniciar sesión", style="Title.TLabel").pack(pady=(0, 10))

        form = ttk.Frame(frame)
        form.pack(pady=5)

        ttk.Label(form, text="Usuario:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.entry_user = ttk.Entry(form, width=30)
        self.entry_user.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(form, text="Contraseña:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.entry_pass = ttk.Entry(form, width=30, show="*")
        self.entry_pass.grid(row=1, column=1, padx=5, pady=5)

        btns = ttk.Frame(frame)
        btns.pack(pady=10)
        ttk.Button(btns, text="Entrar", command=self.login).grid(row=0, column=0, padx=5)
        ttk.Button(btns, text="Registrar", command=self.build_register).grid(row=0, column=1, padx=5)

    def login(self):
        usuario = self.entry_user.get().strip()
        password = self.entry_pass.get()

        if auth.autenticar(usuario, password):
            self.usuario_actual = usuario
            self.password_actual = password   # la guardamos para descifrar la clave privada
            self.build_panel()
        else:
            self.usuario_actual = None
            self.password_actual = None
            messagebox.showerror("Login", "Usuario o contraseña incorrectos.")

    # ---------------- REGISTRO ----------------
    def build_register(self):
        self._clear_root()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Registro de usuario", style="Title.TLabel").pack(pady=10)

        form = ttk.Frame(frame)
        form.pack(pady=5)

        campos = [
            ("Usuario (login):", "usuario"),
            ("Contraseña:", "password"),
            ("Nombre completo:", "nombre"),
            ("Correo electrónico:", "email"),
            ("Fecha de nacimiento (YYYY-MM-DD):", "fecha"),
        ]
        self.reg_entries = {}

        for i, (texto, clave) in enumerate(campos):
            ttk.Label(form, text=texto).grid(row=i, column=0, sticky="e", padx=5, pady=4)
            show = "*" if clave == "password" else None
            e = ttk.Entry(form, show=show, width=32)
            e.grid(row=i, column=1, sticky="w", padx=5, pady=4)
            self.reg_entries[clave] = e

        btns = ttk.Frame(frame)
        btns.pack(pady=10)
        ttk.Button(btns, text="Crear cuenta", command=self._registrar_usuario).grid(row=0, column=0, padx=5)
        ttk.Button(btns, text="Volver", command=self.build_login).grid(row=0, column=1, padx=5)

    def _registrar_usuario(self):
        usuario = self.reg_entries["usuario"].get().strip()
        password = self.reg_entries["password"].get()
        nombre = self.reg_entries["nombre"].get().strip()
        email = self.reg_entries["email"].get().strip()
        fecha_nac = self.reg_entries["fecha"].get().strip()

        if not usuario or not password:
            messagebox.showwarning("Registro", "Usuario y contraseña son obligatorios.")
            return

        try:
            auth.registrar(usuario, password)
        except Exception as e:
            messagebox.showerror("Registro", f"Error al registrar: {e}")
            return

        usuarios = management._leer_json(auth.RUTA_USUARIOS, {})
        perfil = usuarios.get(usuario, {})
        perfil.update({
            "nombre": nombre,
            "email": email,
            "fecha_nacimiento": fecha_nac,
        })
        usuarios[usuario] = perfil
        management._guardar_json(auth.RUTA_USUARIOS, usuarios)

        messagebox.showinfo("Registro", "Usuario registrado correctamente.")
        self.build_login()

    # ---------------- PANEL PRINCIPAL ----------------
    def build_panel(self):
        self._clear_root()

        header = ttk.Frame(self.root, padding=(10, 5))
        header.pack(fill="x")
        ttk.Label(header, text=f"Usuario: {self.usuario_actual}", style="Title.TLabel").pack(side="left")

        # Botón nuevo: Mis reservas
        ttk.Button(header, text="Mis reservas", command=self.ventana_reservas).pack(side="right", padx=10)

        # Vuelos
        marco_vuelos = ttk.Labelframe(self.root, text="Vuelos disponibles")
        marco_vuelos.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        frame_v = ttk.Frame(marco_vuelos)
        frame_v.pack(fill="both", expand=True)

        scroll_v = ttk.Scrollbar(frame_v)
        scroll_v.pack(side="right", fill="y")

        self.lista_vuelos = tk.Listbox(
            frame_v,
            height=12,
            yscrollcommand=scroll_v.set,
            font=("Segoe UI", 10)
        )
        self.lista_vuelos.pack(side="left", fill="both", expand=True)
        scroll_v.config(command=self.lista_vuelos.yview)

        btns_v = ttk.Frame(marco_vuelos)
        btns_v.pack(pady=5)
        ttk.Button(btns_v, text="Reservar seleccionado", command=self.reservar_vuelo).grid(row=0, column=0, padx=5)
        ttk.Button(btns_v, text="Refrescar", command=self.refrescar_vuelos).grid(row=0, column=1, padx=5)
        ttk.Button(btns_v, text="Cerrar sesión", command=self.build_login).grid(row=0, column=2, padx=5)

        self.refrescar_vuelos()

    def refrescar_vuelos(self):
        """Rellena la lista de vuelos desde management.vuelos_disponibles()."""
        self.lista_vuelos.delete(0, tk.END)
        vuelos = management.vuelos_disponibles()
        if not vuelos:
            self.lista_vuelos.insert(tk.END, "No hay vuelos en data/vuelos.json")
            return

        for v in vuelos:
            linea = (
                f"{v.get('numero_vuelo', 'N/A')} | "
                f"{v.get('fecha', '')} · {v.get('hora_salida', '')}-{v.get('hora_llegada', '')} | "
                f"{v.get('lugar_origen', '')} → {v.get('lugar_destino', '')}"
            )
            self.lista_vuelos.insert(tk.END, linea)

    def reservar_vuelo(self):
        """Crea una reserva CIFRADA y FIRMADA del vuelo seleccionado usando management.py."""
        sel = self.lista_vuelos.curselection()
        if not sel:
            messagebox.showwarning("Reserva", "Selecciona un vuelo primero.")
            return

        linea = self.lista_vuelos.get(sel[0])
        numero_vuelo = linea.split("|")[0].strip()

        if not self.password_actual:
            messagebox.showerror("Reserva", "No hay contraseña almacenada en la sesión.")
            return

        ok, msg = management.crear_reserva(
            self.usuario_actual,
            numero_vuelo,
            self.password_actual.encode("utf-8")
        )
        if ok:
            messagebox.showinfo("Reserva", msg)
        else:
            messagebox.showerror("Reserva", msg)

    # ---------------- VENTANA "MIS RESERVAS" ----------------
    def ventana_reservas(self):
        if not self.usuario_actual or not self.password_actual:
            messagebox.showerror("Mis reservas", "No hay usuario autenticado.")
            return

        try:
            passphrase = self.password_actual.encode("utf-8")
            reservas = management.cargar_reservas_descifradas(self.usuario_actual, passphrase)
        except Exception as e:
            messagebox.showerror("Mis reservas", f"No se pudieron cargar las reservas:\n{e}")
            return

        win = tk.Toplevel(self.root)
        win.title("Mis reservas")
        win.geometry("750x400")

        lista = tk.Listbox(win, font=("Segoe UI", 10))
        lista.pack(fill="both", expand=True, padx=10, pady=10)

        if not reservas:
            lista.insert(tk.END, "No hay reservas.")
            return

        for r in reservas:
            v = r.get("vuelo", {})

            if r.get("_tiene_firma"):
                estado_firma = "OK" if r.get("_firma_valida") else "ERROR"
            else:
                estado_firma = "SIN FIRMA"

            linea = (
                f"{v.get('numero_vuelo', '??')} | "
                f"{v.get('fecha', '')} · {v.get('hora_salida', '')}-{v.get('hora_llegada', '')} | "
                f"{v.get('lugar_origen', '')} → {v.get('lugar_destino', '')} | "
                f"Asiento {r.get('asiento', '?')} | "
                f"Business: {r.get('business', False)} | "
                f"Firma: {estado_firma}"
            )

            lista.insert(tk.END, linea)

    # ---------------- UTILIDADES UI ----------------
    def _clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    AppVuelos()
