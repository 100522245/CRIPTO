# interfaz_vuelos.py
import tkinter as tk
from tkinter import messagebox
import json
import base64

# Importar tus módulos existentes
import autentificacion as auth
import cifrado_descifrado as crypto
import etiquetas as hmac_utils

RSA_PASSWORD = b"clave_segura_usuario"

class AppVuelos:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Compra Segura de Vuelos")
        self.root.geometry("600x500")
        self.rsa_priv, self.rsa_pub = crypto.generate_rsa_keys(RSA_PASSWORD)
        self.usuario_actual = None
        self.build_login()
        self.root.mainloop()

    def build_login(self):
        self.clear_root()
        tk.Label(self.root, text="Usuario:").pack()
        self.usuario_entry = tk.Entry(self.root)
        self.usuario_entry.pack()
        tk.Label(self.root, text="Contraseña:").pack()
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack()
        tk.Button(self.root, text="Registrar", command=self.registrar).pack(pady=5)
        tk.Button(self.root, text="Iniciar sesión", command=self.login).pack(pady=5)

    def build_vuelo(self):
        self.clear_root()
        tk.Label(self.root, text=f"Usuario: {self.usuario_actual}").pack()
        self.campos = {}
        for campo in ["numero_vuelo","nombre_pasajero","lugar_destino","lugar_llegada","hora_salida","hora_llegada"]:
            tk.Label(self.root, text=campo).pack()
            entry = tk.Entry(self.root)
            entry.pack()
            self.campos[campo] = entry
        tk.Button(self.root, text="Cifrar vuelo", command=self.cifrar_vuelo).pack(pady=5)
        self.output_text = tk.Text(self.root, height=15)
        self.output_text.pack()

    def registrar(self):
        try:
            auth.registrar(self.usuario_entry.get(), self.pass_entry.get())
            messagebox.showinfo("Registro", "Usuario registrado correctamente")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def login(self):
        if auth.autenticar(self.usuario_entry.get(), self.pass_entry.get()):
            self.usuario_actual = self.usuario_entry.get()
            self.build_vuelo()
        else:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos")

    def cifrar_vuelo(self):
        vuelo = {k: v.get() for k, v in self.campos.items()}
        data_bytes = json.dumps(vuelo, indent=4).encode()
        aad = b"informacion de vuelo autenticada"
        encrypted = crypto.encrypt_message(data_bytes, aad, self.rsa_pub)
        tag = hmac_utils.crear_hmac(data_bytes)
        decrypted = crypto.decrypt_message(encrypted, self.rsa_priv, RSA_PASSWORD)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, "✅ Datos cifrados:\n")
        self.output_text.insert(tk.END, encrypted.decode() + "\n\n")
        self.output_text.insert(tk.END, "✅ HMAC generado: " + base64.b64encode(tag).decode() + "\n")
        self.output_text.insert(tk.END, "✅ Datos descifrados:\n" + decrypted.decode() + "\n")
        self.output_text.insert(tk.END, "✅ HMAC verificado: " + str(hmac_utils.verificar_hmac(decrypted, tag)) + "\n")

    def clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    AppVuelos()
