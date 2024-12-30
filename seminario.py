import asyncio
from bleak import BleakScanner
import sqlite3
from datetime import datetime, timedelta
import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

class BluetoothSecurityMonitorGUI:
    def __init__(self, db_path="bluetooth_security.db"):
        self.db_path = db_path
        self.setup_database()
        self.load_trusted_devices()
        self.load_dangerous_devices()

        # ConfiguraciÃ³n
        self.alert_threshold_rssi = -70  # RSSI >= -70 dB para detecciÃ³n normal
        self.dangerous_threshold_rssi = -60  # RSSI >= -60 dB para dispositivos peligrosos
        self.alert_states = {}  # Diccionario para rastrear el estado de alertas
        self.scan_results = []

        # Cola para comunicar entre hilos
        self.queue = queue.Queue()

        # Mapas para gestionar dispositivos Ãºnicos en la GUI
        self.device_map = {}
        self.combo_devices_set = set()

        # Configurar GUI
        self.root = tk.Tk()
        self.root.title("Monitor de Seguridad Bluetooth")
        self.root.geometry("1200x900")  # Aumentado para acomodar mÃ¡s pestaÃ±as

        # Crear Notebook (pestaÃ±as)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # PestaÃ±a Actual
        self.current_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.current_frame, text="Dispositivos Actuales")
        self.setup_current_tab()

        # PestaÃ±a Historial
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="Historial de Detecciones")
        self.setup_history_tab()

        # PestaÃ±a Alertas
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Alertas")
        self.setup_alerts_tab()

        # PestaÃ±a GrÃ¡ficos
        self.graph_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.graph_frame, text="GrÃ¡ficos de RSSI")
        self.setup_graph_tab()

        # PestaÃ±a GestiÃ³n de Dispositivos
        self.management_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.management_frame, text="GestiÃ³n de Dispositivos")
        self.setup_management_tab()

        # BotÃ³n para cerrar
        btn_close = ttk.Button(self.root, text="Cerrar", command=self.on_close)
        btn_close.pack(pady=10)

        # Iniciar el monitoreo en un hilo separado
        self.monitoring_thread = threading.Thread(target=self.start_monitoring, daemon=True)
        self.monitoring_thread.start()

        # Iniciar la actualizaciÃ³n de la GUI
        self.root.after(1000, self.process_queue)

    def setup_current_tab(self):
        # Crear Treeview para mostrar dispositivos actuales
        self.tree = ttk.Treeview(self.current_frame, columns=('MAC', 'Nombre', 'RSSI'), show='headings')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Nombre', text='Nombre')
        self.tree.heading('RSSI', text='RSSI (dB)')
        self.tree.column('MAC', width=300)
        self.tree.column('Nombre', width=500)
        self.tree.column('RSSI', width=150, anchor='center')
        self.tree.pack(fill=tk.BOTH, expand=True)

    def setup_history_tab(self):
        # Crear Treeview para mostrar historial de detecciones
        self.history_tree = ttk.Treeview(self.history_frame, columns=('Timestamp', 'MAC', 'Nombre', 'RSSI', 'Tipo'), show='headings')
        self.history_tree.heading('Timestamp', text='Fecha y Hora')
        self.history_tree.heading('MAC', text='MAC Address')
        self.history_tree.heading('Nombre', text='Nombre')
        self.history_tree.heading('RSSI', text='RSSI (dB)')
        self.history_tree.heading('Tipo', text='Tipo de Alerta')
        self.history_tree.column('Timestamp', width=250)
        self.history_tree.column('MAC', width=300)
        self.history_tree.column('Nombre', width=400)
        self.history_tree.column('RSSI', width=150, anchor='center')
        self.history_tree.column('Tipo', width=200, anchor='center')
        self.history_tree.pack(fill=tk.BOTH, expand=True)

        # Botones para actualizar y limpiar el historial
        button_frame = ttk.Frame(self.history_frame)
        button_frame.pack(pady=10)

        btn_refresh = ttk.Button(button_frame, text="Actualizar Historial", command=self.load_history)
        btn_refresh.pack(side=tk.LEFT, padx=5)

        btn_cleanup = ttk.Button(button_frame, text="Limpiar Alertas Antiguas", command=lambda: self.cleanup_old_alerts(days=30))
        btn_cleanup.pack(side=tk.LEFT, padx=5)

        # BotÃ³n para eliminar todo el historial
        btn_delete_all_history = ttk.Button(button_frame, text="Eliminar Todo el Historial", command=self.delete_all_history)
        btn_delete_all_history.pack(side=tk.LEFT, padx=5)

    def setup_alerts_tab(self):
        # Crear Treeview para mostrar alertas de dispositivos peligrosos
        self.alerts_tree = ttk.Treeview(self.alerts_frame, columns=('Timestamp', 'MAC', 'Nombre', 'RSSI', 'Tipo'), show='headings')
        self.alerts_tree.heading('Timestamp', text='Fecha y Hora')
        self.alerts_tree.heading('MAC', text='MAC Address')
        self.alerts_tree.heading('Nombre', text='Nombre')
        self.alerts_tree.heading('RSSI', text='RSSI (dB)')
        self.alerts_tree.heading('Tipo', text='Tipo de Alerta')
        self.alerts_tree.column('Timestamp', width=250)
        self.alerts_tree.column('MAC', width=300)
        self.alerts_tree.column('Nombre', width=400)
        self.alerts_tree.column('RSSI', width=150, anchor='center')
        self.alerts_tree.column('Tipo', width=200, anchor='center')
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)

        # Botones para actualizar las alertas
        button_frame = ttk.Frame(self.alerts_frame)
        button_frame.pack(pady=10)

        btn_refresh_alerts = ttk.Button(button_frame, text="Actualizar Alertas", command=self.load_alerts)
        btn_refresh_alerts.pack(side=tk.LEFT, padx=5)

        # BotÃ³n para eliminar todas las alertas guardadas
        btn_delete_all_alerts = ttk.Button(button_frame, text="Eliminar Todas las Alertas", command=self.delete_all_alerts)
        btn_delete_all_alerts.pack(side=tk.LEFT, padx=5)

    def setup_graph_tab(self):
        # Crear elementos para seleccionar dispositivo
        selection_frame = ttk.Frame(self.graph_frame)
        selection_frame.pack(pady=10)

        ttk.Label(selection_frame, text="Selecciona un dispositivo:").pack(side=tk.LEFT, padx=5)

        self.device_selection = ttk.Combobox(selection_frame, state="readonly")
        self.device_selection.pack(side=tk.LEFT, padx=5)
        self.device_selection.bind("<<ComboboxSelected>>", self.update_graph)

        # Crear espacio para el grÃ¡fico
        self.figure, self.ax = plt.subplots(figsize=(10,6))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def setup_management_tab(self):
        # Crear Notebook interno para Fiables y Peligrosos
        management_notebook = ttk.Notebook(self.management_frame)
        management_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # PestaÃ±a Fiables
        self.fiables_tab = ttk.Frame(management_notebook)
        management_notebook.add(self.fiables_tab, text="Dispositivos Fiables")
        self.setup_fiables_tab()

        # PestaÃ±a Peligrosos
        self.peligrosos_tab = ttk.Frame(management_notebook)
        management_notebook.add(self.peligrosos_tab, text="Dispositivos Peligrosos")
        self.setup_peligrosos_tab()

    def setup_fiables_tab(self):
        # Crear Treeview para dispositivos fiables
        self.fiables_tree = ttk.Treeview(self.fiables_tab, columns=('MAC', 'Nombre'), show='headings')
        self.fiables_tree.heading('MAC', text='MAC Address')
        self.fiables_tree.heading('Nombre', text='Nombre')
        self.fiables_tree.column('MAC', width=300)
        self.fiables_tree.column('Nombre', width=500)
        self.fiables_tree.pack(fill=tk.BOTH, expand=True)

        # Frame para aÃ±adir nuevos dispositivos fiables
        add_frame = ttk.LabelFrame(self.fiables_tab, text="AÃ±adir Nuevo Dispositivo Fiable")
        add_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(add_frame, text="MAC Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.reliable_mac_entry = ttk.Entry(add_frame, width=30)
        self.reliable_mac_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(add_frame, text="Nombre:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.reliable_name_entry = ttk.Entry(add_frame, width=30)
        self.reliable_name_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_add_fiable = ttk.Button(add_frame, text="AÃ±adir Dispositivo Fiable", command=self.add_trusted_device_gui)
        btn_add_fiable.grid(row=2, column=0, columnspan=2, pady=10)

        # BotÃ³n para eliminar
        btn_delete_fiable = ttk.Button(self.fiables_tab, text="Eliminar Seleccionado", command=self.delete_trusted_device)
        btn_delete_fiable.pack(pady=10)

        # Cargar dispositivos fiables en el Treeview
        self.load_trusted_devices_into_tree()

    def setup_peligrosos_tab(self):
        # Crear Treeview para dispositivos peligrosos
        self.peligrosos_tree = ttk.Treeview(self.peligrosos_tab, columns=('MAC', 'Nombre'), show='headings')
        self.peligrosos_tree.heading('MAC', text='MAC Address')
        self.peligrosos_tree.heading('Nombre', text='Nombre')
        self.peligrosos_tree.column('MAC', width=300)
        self.peligrosos_tree.column('Nombre', width=500)
        self.peligrosos_tree.pack(fill=tk.BOTH, expand=True)

        # Frame para aÃ±adir nuevos dispositivos peligrosos
        add_frame = ttk.LabelFrame(self.peligrosos_tab, text="AÃ±adir Nuevo Dispositivo Peligroso")
        add_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(add_frame, text="MAC Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.dangerous_mac_entry = ttk.Entry(add_frame, width=30)
        self.dangerous_mac_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(add_frame, text="Nombre:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.dangerous_name_entry = ttk.Entry(add_frame, width=30)
        self.dangerous_name_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_add_peligroso = ttk.Button(add_frame, text="AÃ±adir Dispositivo Peligroso", command=self.add_dangerous_device_gui)
        btn_add_peligroso.grid(row=2, column=0, columnspan=2, pady=10)

        # BotÃ³n para eliminar
        btn_delete_peligroso = ttk.Button(self.peligrosos_tab, text="Eliminar Seleccionado", command=self.delete_dangerous_device)
        btn_delete_peligroso.pack(pady=10)

        # Cargar dispositivos peligrosos en el Treeview
        self.load_dangerous_devices_into_tree()

    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Tablas
        c.execute('''CREATE TABLE IF NOT EXISTS trusted_devices
                    (mac_address TEXT PRIMARY KEY, 
                     device_name TEXT,
                     first_seen TEXT,
                     last_seen TEXT,
                     notes TEXT)''')

        c.execute('''CREATE TABLE IF NOT EXISTS dangerous_devices
                    (mac_address TEXT PRIMARY KEY, 
                     device_name TEXT,
                     first_seen TEXT,
                     last_seen TEXT,
                     notes TEXT)''')

        c.execute('''CREATE TABLE IF NOT EXISTS alerts
                    (timestamp TEXT,
                     mac_address TEXT,
                     device_name TEXT,
                     rssi INTEGER,
                     alert_type TEXT)''')

        conn.commit()
        conn.close()

    def load_trusted_devices(self):
        self.trusted_devices = set()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for row in c.execute('SELECT mac_address FROM trusted_devices'):
            self.trusted_devices.add(row[0].upper())
        conn.close()

    def load_dangerous_devices(self):
        self.dangerous_devices_mac = set()
        self.dangerous_devices_names = set()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for row in c.execute('SELECT mac_address, device_name FROM dangerous_devices'):
            self.dangerous_devices_mac.add(row[0].upper())
            if row[1]:
                self.dangerous_devices_names.add(row[1].upper())
        conn.close()

    def add_trusted_device_gui(self):
        mac = self.reliable_mac_entry.get().strip().upper()
        name = self.reliable_name_entry.get().strip()

        if not self.validate_mac(mac):
            messagebox.showerror("Error", "La direcciÃ³n MAC introducida no es vÃ¡lida.")
            return

        if mac in self.trusted_devices:
            messagebox.showwarning("Advertencia", "Este dispositivo ya estÃ¡ en la lista de fiables.")
            return

        self.add_trusted_device(mac, name)
        messagebox.showinfo("Ã‰xito", f"Dispositivo fiable aÃ±adido: {mac}")
        self.reliable_mac_entry.delete(0, tk.END)
        self.reliable_name_entry.delete(0, tk.END)

        # Actualizar Treeview de fiables
        self.fiables_tree.insert('', 'end', values=(mac, name or 'Desconocido'))

    def add_dangerous_device_gui(self):
        mac = self.dangerous_mac_entry.get().strip().upper()
        name = self.dangerous_name_entry.get().strip()

        if not self.validate_mac(mac):
            messagebox.showerror("Error", "La direcciÃ³n MAC introducida no es vÃ¡lida.")
            return

        if mac in self.dangerous_devices_mac or name.upper() in self.dangerous_devices_names:
            messagebox.showwarning("Advertencia", "Este dispositivo ya estÃ¡ en la lista de peligrosos.")
            return

        self.add_dangerous_device(mac, name)
        messagebox.showinfo("Ã‰xito", f"Dispositivo peligroso aÃ±adido: {mac} - {name}")
        self.dangerous_mac_entry.delete(0, tk.END)
        self.dangerous_name_entry.delete(0, tk.END)

        # Actualizar Treeview de peligrosos
        self.peligrosos_tree.insert('', 'end', values=(mac, name or 'Desconocido'))

    def validate_mac(self, mac):
        # Formato MAC estÃ¡ndar: "XX:XX:XX:XX:XX:XX"
        if len(mac) != 17:
            return False
        allowed = "0123456789ABCDEF:"
        for char in mac:
            if char not in allowed:
                return False
        return True

    def add_trusted_device(self, mac_address, device_name, notes=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.now().isoformat()

        c.execute('''INSERT OR REPLACE INTO trusted_devices 
                    (mac_address, device_name, first_seen, last_seen, notes)
                    VALUES (?, ?, ?, ?, ?)''',
                 (mac_address, device_name, now, now, notes))

        conn.commit()
        conn.close()
        self.trusted_devices.add(mac_address)
        print(f"\nâœ… Dispositivo aÃ±adido a la lista de confianza: {device_name} ({mac_address})")

    def add_dangerous_device(self, mac_address, device_name, notes=""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.now().isoformat()

        c.execute('''INSERT OR REPLACE INTO dangerous_devices 
                    (mac_address, device_name, first_seen, last_seen, notes)
                    VALUES (?, ?, ?, ?, ?)''',
                 (mac_address, device_name, now, now, notes))

        conn.commit()
        conn.close()
        self.dangerous_devices_mac.add(mac_address)
        if device_name:
            self.dangerous_devices_names.add(device_name.upper())
        print(f"\nâœ… Dispositivo aÃ±adido a la lista de peligrosos: {device_name} ({mac_address})")

    def log_alert(self, mac_address, device_name, rssi, alert_type):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = datetime.now().isoformat()

        c.execute('''INSERT INTO alerts 
                    (timestamp, mac_address, device_name, rssi, alert_type)
                    VALUES (?, ?, ?, ?, ?)''',
                 (now, mac_address, device_name, rssi, alert_type))

        conn.commit()
        conn.close()

    def add_device_to_gui(self, device):
        mac = device['mac'].upper()
        name = device['name'] or 'Desconocido'
        rssi = device['rssi']

        if mac in self.device_map:
            # Actualizar el RSSI si el dispositivo ya existe
            item_id = self.device_map[mac]
            self.tree.item(item_id, values=(mac, name, rssi))
        else:
            # Insertar un nuevo dispositivo
            item_id = self.tree.insert('', 'end', values=(mac, name, rssi))
            self.device_map[mac] = item_id
            # AÃ±adir al Combobox si no estÃ¡ presente
            if mac not in self.combo_devices_set:
                self.combo_devices_set.add(mac)
                self.device_selection['values'] = sorted(list(self.combo_devices_set))
                print(f"Dispositivo aÃ±adido al Combobox: {mac}")  # Debug print

        # Ordenar la Treeview despuÃ©s de cada inserciÃ³n o actualizaciÃ³n
        self.sort_treeview()

    def sort_treeview(self):
        # Obtener todos los items
        items = self.tree.get_children()
        # Obtener los valores para ordenar
        data = []
        for item in items:
            values = self.tree.item(item, 'values')
            mac, name, rssi = values
            try:
                rssi = int(rssi)
            except ValueError:
                rssi = -100  # Valor por defecto si no se puede convertir
            data.append((item, rssi))

        # Ordenar los datos por RSSI descendente
        data.sort(key=lambda x: x[1], reverse=True)

        # Reordenar los items en la Treeview
        for index, (item, _) in enumerate(data):
            self.tree.move(item, '', index)

    def process_queue(self):
        try:
            while True:
                device = self.queue.get_nowait()
                self.add_device_to_gui(device)
                self.handle_alert(device)
        except queue.Empty:
            pass
        finally:
            self.root.after(1000, self.process_queue)

    def handle_alert(self, device):
        mac_upper = device['mac'].upper()
        name_upper = (device['name'] or 'Desconocido').upper()
        alert_type = "deteccion"

        # Verificar si la MAC o el nombre estÃ¡n en la lista de dispositivos peligrosos
        is_dangerous = (mac_upper in self.dangerous_devices_mac or name_upper in self.dangerous_devices_names)
        is_alert = is_dangerous and device['rssi'] >= self.dangerous_threshold_rssi

        previous_alert = self.alert_states.get(mac_upper, False)

        if is_alert and not previous_alert:
            # Nueva alerta de peligro
            alert_type = "alerta_peligro"
            self.log_alert(device['mac'], device['name'], device['rssi'], alert_type)
            self.insert_history_row(datetime.now().isoformat(), device, alert_type)
            self.add_alert_to_gui(device)
            self.alert_states[mac_upper] = True
            print(f"âœ… Alerta de peligro para: {device['name']} ({mac_upper}) con RSSI: {device['rssi']}")
        elif not is_alert and previous_alert:
            # El dispositivo ya no estÃ¡ en estado de alerta
            alert_type = "alerta_cleared"
            self.log_alert(device['mac'], device['name'], device['rssi'], alert_type)
            self.insert_history_row(datetime.now().isoformat(), device, alert_type)
            self.alert_states[mac_upper] = False
            print(f"ðŸ”” Alerta despejada para: {device['name']} ({mac_upper}) con RSSI: {device['rssi']}")

        # Siempre registrar detecciones
        if not is_alert:
            # Log de detecciÃ³n normal
            self.log_alert(device['mac'], device['name'], device['rssi'], alert_type)
            if self.notebook.index(self.notebook.select()) == 1:
                self.insert_history_row(datetime.now().isoformat(), device, alert_type)
            print(f"ðŸ” DetecciÃ³n para: {device['name']} ({mac_upper}) con RSSI: {device['rssi']}")

        # AÃ±adir el dispositivo al Combobox si es nuevo
        if mac_upper not in self.combo_devices_set:
            self.combo_devices_set.add(mac_upper)
            self.device_selection['values'] = sorted(list(self.combo_devices_set))
            print(f"Dispositivo aÃ±adido al Combobox: {mac_upper}")  # Debug print

    def insert_history_row(self, timestamp, device, alert_type):
        self.history_tree.insert('', 'end', values=(timestamp, device['mac'], device['name'] or 'Desconocido', device['rssi'], alert_type))

    def add_alert_to_gui(self, device):
        timestamp = datetime.now().isoformat()
        self.alerts_tree.insert('', 'end', values=(timestamp, device['mac'], device['name'] or 'Desconocido', device['rssi'], "alerta_peligro"))

    def load_history(self):
        # Limpiar el Treeview de historial
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''SELECT timestamp, mac_address, device_name, rssi, alert_type
                    FROM alerts 
                    WHERE alert_type = "deteccion" OR alert_type = "alerta_peligro" OR alert_type = "alerta_cleared"
                    ORDER BY timestamp DESC''')

        rows = c.fetchall()
        conn.close()

        for row in rows:
            timestamp, mac, name, rssi, alert_type = row
            self.history_tree.insert('', 'end', values=(timestamp, mac, name or 'Desconocido', rssi, alert_type))

        # Populate the Combobox with existing devices
        self.populate_device_selection()

    def load_alerts(self):
        # Limpiar el Treeview de alertas
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''SELECT timestamp, mac_address, device_name, rssi, alert_type
                    FROM alerts 
                    WHERE alert_type = "alerta_peligro"
                    ORDER BY timestamp DESC''')

        rows = c.fetchall()
        conn.close()

        for row in rows:
            timestamp, mac, name, rssi, alert_type = row
            self.alerts_tree.insert('', 'end', values=(timestamp, mac, name or 'Desconocido', rssi, alert_type))

    def cleanup_old_alerts(self, days=30):
        """Elimina las alertas que sean mÃ¡s antiguas que el nÃºmero de dÃ­as especificado y optimiza la base de datos."""
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_iso = cutoff_date.isoformat()

        try:
            # Primera conexiÃ³n para eliminar alertas antiguas
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''DELETE FROM alerts WHERE timestamp < ?''', (cutoff_iso,))
            deleted_rows = c.rowcount
            conn.commit()
            conn.close()

            # Segunda conexiÃ³n para ejecutar VACUUM
            conn_vacuum = sqlite3.connect(self.db_path)
            c_vacuum = conn_vacuum.cursor()
            c_vacuum.execute('VACUUM')  # Optimiza la base de datos
            conn_vacuum.commit()
            conn_vacuum.close()

            print(f"\nâœ… {deleted_rows} alertas eliminadas que son anteriores a {cutoff_iso}.")
            messagebox.showinfo("Limpieza de Alertas", f"Se han eliminado {deleted_rows} alertas antiguas y optimizado la base de datos.")

            # Actualizar las pestaÃ±as de Historial y Alertas
            self.load_history()
            self.load_alerts()
        except sqlite3.OperationalError as e:
            print(f"Error durante la limpieza de alertas: {e}")
            messagebox.showerror("Error de Limpieza", f"No se pudo limpiar las alertas antiguas: {e}")
        except Exception as e:
            print(f"Error inesperado durante la limpieza de alertas: {e}")
            messagebox.showerror("Error de Limpieza", f"OcurriÃ³ un error inesperado: {e}")

    def delete_all_history(self):
        """Elimina todo el historial de detecciones."""
        confirm = messagebox.askyesno("Confirmar EliminaciÃ³n", "Â¿EstÃ¡s seguro de que deseas eliminar todo el historial de detecciones?")
        if not confirm:
            return

        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('DELETE FROM alerts')
            deleted_rows = c.rowcount
            conn.commit()
            conn.close()

            # Optimizar la base de datos
            conn_vacuum = sqlite3.connect(self.db_path)
            c_vacuum = conn_vacuum.cursor()
            c_vacuum.execute('VACUUM')
            conn_vacuum.commit()
            conn_vacuum.close()

            print(f"\nâœ… Todo el historial de detecciones eliminado. Filas eliminadas: {deleted_rows}")
            messagebox.showinfo("Eliminar Historial", f"Se ha eliminado todo el historial de detecciones. Filas eliminadas: {deleted_rows}")

            # Actualizar la pestaÃ±a de Historial y Alertas
            self.load_history()
            self.load_alerts()
        except sqlite3.OperationalError as e:
            print(f"Error al eliminar el historial: {e}")
            messagebox.showerror("Error de EliminaciÃ³n", f"No se pudo eliminar el historial: {e}")
        except Exception as e:
            print(f"Error inesperado al eliminar el historial: {e}")
            messagebox.showerror("Error de EliminaciÃ³n", f"OcurriÃ³ un error inesperado: {e}")

    def delete_all_alerts(self):
        """Elimina todas las alertas guardadas de tipo 'alerta_peligro'."""
        confirm = messagebox.askyesno("Confirmar EliminaciÃ³n", "Â¿EstÃ¡s seguro de que deseas eliminar todas las alertas guardadas?")
        if not confirm:
            return

        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('DELETE FROM alerts WHERE alert_type = "alerta_peligro"')
            deleted_rows = c.rowcount
            conn.commit()
            conn.close()

            # Optimizar la base de datos
            conn_vacuum = sqlite3.connect(self.db_path)
            c_vacuum = conn_vacuum.cursor()
            c_vacuum.execute('VACUUM')
            conn_vacuum.commit()
            conn_vacuum.close()

            print(f"\nâœ… Todas las alertas guardadas eliminadas. Filas eliminadas: {deleted_rows}")
            messagebox.showinfo("Eliminar Alertas", f"Se han eliminado todas las alertas guardadas. Filas eliminadas: {deleted_rows}")

            # Actualizar la pestaÃ±a de Alertas
            self.load_alerts()
        except sqlite3.OperationalError as e:
            print(f"Error al eliminar las alertas: {e}")
            messagebox.showerror("Error de EliminaciÃ³n", f"No se pudo eliminar las alertas: {e}")
        except Exception as e:
            print(f"Error inesperado al eliminar las alertas: {e}")
            messagebox.showerror("Error de EliminaciÃ³n", f"OcurriÃ³ un error inesperado: {e}")

    def delete_trusted_device(self):
        selected_item = self.fiables_tree.selection()
        if not selected_item:
            messagebox.showwarning("Eliminar Dispositivo", "Por favor, selecciona un dispositivo fiable para eliminar.")
            return

        for item in selected_item:
            mac = self.fiables_tree.item(item, 'values')[0]
            confirm = messagebox.askyesno("Confirmar EliminaciÃ³n", f"Â¿EstÃ¡s seguro de que deseas eliminar el dispositivo fiable:\nMAC: {mac}?")
            if confirm:
                self.remove_trusted_device(mac)
                self.fiables_tree.delete(item)
                self.trusted_devices.discard(mac)
                print(f"âœ… Dispositivo fiable eliminado: {mac}")

    def delete_dangerous_device(self):
        selected_item = self.peligrosos_tree.selection()
        if not selected_item:
            messagebox.showwarning("Eliminar Dispositivo", "Por favor, selecciona un dispositivo peligroso para eliminar.")
            return

        for item in selected_item:
            mac = self.peligrosos_tree.item(item, 'values')[0]
            name = self.peligrosos_tree.item(item, 'values')[1].upper()
            confirm = messagebox.askyesno("Confirmar EliminaciÃ³n", f"Â¿EstÃ¡s seguro de que deseas eliminar el dispositivo peligroso:\nMAC: {mac}\nNombre: {name}?")
            if confirm:
                self.remove_dangerous_device(mac, name)
                self.peligrosos_tree.delete(item)
                self.dangerous_devices_mac.discard(mac)
                self.dangerous_devices_names.discard(name)
                print(f"âœ… Dispositivo peligroso eliminado: {mac} - {name}")

    def remove_trusted_device(self, mac_address):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM trusted_devices WHERE mac_address = ?', (mac_address,))
        conn.commit()
        conn.close()

    def remove_dangerous_device(self, mac_address, device_name):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('DELETE FROM dangerous_devices WHERE mac_address = ?', (mac_address,))
        conn.commit()
        conn.close()

    def load_trusted_devices_into_tree(self):
        # Limpiar el Treeview de fiables
        for item in self.fiables_tree.get_children():
            self.fiables_tree.delete(item)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('SELECT mac_address, device_name FROM trusted_devices')
        rows = c.fetchall()
        conn.close()

        for row in rows:
            mac, name = row
            self.fiables_tree.insert('', 'end', values=(mac, name or 'Desconocido'))

    def load_dangerous_devices_into_tree(self):
        # Limpiar el Treeview de peligrosos
        for item in self.peligrosos_tree.get_children():
            self.peligrosos_tree.delete(item)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('SELECT mac_address, device_name FROM dangerous_devices')
        rows = c.fetchall()
        conn.close()

        for row in rows:
            mac, name = row
            self.peligrosos_tree.insert('', 'end', values=(mac, name or 'Desconocido'))

    def populate_device_selection(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute('''SELECT DISTINCT mac_address, device_name FROM alerts 
                    WHERE alert_type = "deteccion" OR alert_type = "alerta_peligro" OR alert_type = "alerta_cleared"''')
        devices = c.fetchall()
        conn.close()

        # Update the set and Combobox
        for row in devices:
            mac, name = row
            if mac and mac.upper() not in self.combo_devices_set:
                self.combo_devices_set.add(mac.upper())
            if name and name.upper() not in self.combo_devices_set:
                self.combo_devices_set.add(name.upper())

        self.device_selection['values'] = sorted(list(self.combo_devices_set))
        print(f"Combobox actualizado con dispositivos: {self.combo_devices_set}")  # Debug print

    def update_graph(self, event):
        selected = self.device_selection.get().upper()
        if not selected:
            return

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Buscar todas las alertas por MAC o por Nombre
        c.execute('''SELECT timestamp, rssi, alert_type 
                    FROM alerts 
                    WHERE (mac_address = ? OR UPPER(device_name) = ?) 
                    ORDER BY timestamp ASC''', (selected, selected))

        rows = c.fetchall()
        conn.close()

        if not rows:
            messagebox.showwarning("No hay datos", "No hay datos disponibles para este dispositivo.")
            return

        # Extraer datos
        timestamps = [datetime.fromisoformat(row[0]) for row in rows]
        rssis = [row[1] for row in rows]
        alert_types = [row[2] for row in rows]

        # Limpiar el grÃ¡fico anterior
        self.ax.clear()

        # Graficar todos los puntos de RSSI
        self.ax.plot(timestamps, rssis, marker='o', linestyle='-', label='RSSI')

        # Resaltar alertas de peligro y despeje
        for timestamp, rssi, alert_type in zip(timestamps, rssis, alert_types):
            if alert_type == "alerta_peligro":
                self.ax.plot(timestamp, rssi, marker='o', color='red', label='Alerta Peligro' if 'Alerta Peligro' not in self.ax.get_legend_handles_labels()[1] else "")
            elif alert_type == "alerta_cleared":
                self.ax.plot(timestamp, rssi, marker='o', color='green', label='Alerta Despejada' if 'Alerta Despejada' not in self.ax.get_legend_handles_labels()[1] else "")

        self.ax.set_title(f"Tendencia de RSSI para {selected}")
        self.ax.set_xlabel("Fecha y Hora")
        self.ax.set_ylabel("RSSI (dB)")
        self.ax.grid(True)
        self.ax.legend()
        self.figure.autofmt_xdate()
        self.canvas.draw()

    def start_monitoring(self):
        try:
            asyncio.run(self.run_monitoring())
        except Exception as e:
            print(f"Error en start_monitoring: {e}")

    async def monitor_devices(self, duration=10.0):
        try:
            devices = await BleakScanner.discover(timeout=duration)
            filtered_devices = [
                {
                    'mac': device.address.upper(),
                    'name': device.name,
                    'rssi': device.rssi
                }
                for device in devices
                if device.rssi is not None and device.rssi >= self.alert_threshold_rssi
            ]

            # Ordenar por RSSI descendente
            filtered_devices.sort(key=lambda d: d['rssi'], reverse=True)

            print("\nDispositivos detectados en este escaneo (ordenados por RSSI):")
            for device in filtered_devices:
                try:
                    print(f"MAC: {device['mac']}, Name: {device['name'] or 'Unknown'}, RSSI: {device['rssi']}")
                except UnicodeEncodeError:
                    print(f"MAC: {device['mac']}, Name: [Nombre no vÃ¡lido], RSSI: {device['rssi']}")

            self.scan_results.append(filtered_devices)

            for device in filtered_devices:
                mac = device['mac']
                name = device['name'] or 'Desconocido'

                # Verificar si el dispositivo no estÃ¡ en la lista de fiables
                if mac not in self.trusted_devices:
                    # Enviar el dispositivo a la cola para evaluar alertas
                    self.queue.put(device)
        except Exception as e:
            print(f"Error durante el monitoreo: {e}")

    async def run_monitoring(self):
        scan_count = 0
        try:
            while True:
                await self.monitor_devices(10.0)
                scan_count += 1
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            print("\nMonitoreo detenido.")
        except Exception as e:
            print(f"Error inesperado en run_monitoring: {e}")

    def on_close(self):
        # MÃ©todo para manejar el cierre de la ventana
        print("Cerrando la aplicaciÃ³n...")
        self.root.quit()

    def run(self):
        self.load_history()
        self.load_alerts()
        self.populate_device_selection()
        # Ejecutar limpieza al iniciar
        self.cleanup_old_alerts(days=30)
        # Programar limpieza diaria
        self.root.after(86400000, lambda: self.schedule_cleanup(30))  # 86400000 ms = 24 horas
        self.root.mainloop()

    def schedule_cleanup(self, days):
        self.cleanup_old_alerts(days=days)
        # Reprogramar la limpieza para el prÃ³ximo dÃ­a
        self.root.after(86400000, lambda: self.schedule_cleanup(days))  # 86400000 ms = 24 horas

if __name__ == "__main__":
    def main():
        monitor = BluetoothSecurityMonitorGUI()
        monitor.run()

    main()
