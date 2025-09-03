# Bluetooth Security Monitor GUI

Aplicación de monitorización de seguridad Bluetooth con interfaz gráfica (Tkinter) que escanea dispositivos BLE con Bleak, registra eventos en SQLite, genera alertas según listas de confianza/peligro y muestra gráficas de RSSI con Matplotlib. Diseñada para pruebas de laboratorio y demostraciones de seguridad.

NOTA SOBRE CODIFICACIÓN:
Si ves caracteres raros (acentos/ñ), guarda los archivos en UTF-8. Opcional: añade al inicio del .py la línea:  # -*- coding: utf-8 -*-

------------------------------------------------------------
CARACTERÍSTICAS
------------------------------------------------------------
- Escaneo BLE periódico con filtrado por umbrales de RSSI.
- Listas gestionadas desde la GUI:
  - Fiables (trusted): dispositivos ignorados en ciclo de alertas.
  - Peligrosos (dangerous): generan alerta si su RSSI supera el umbral.
- Historial persistente en SQLite de detecciones, alertas y despejes.
- Gráficas de RSSI por dispositivo (MAC o nombre) a lo largo del tiempo.
- Limpieza automática del historial (por defecto, >30 días) con VACUUM.
- Interfaz por pestañas: Dispositivos actuales, Historial, Alertas, Gráficos y Gestión.

------------------------------------------------------------
REQUISITOS
------------------------------------------------------------
Python: 3.9 o superior (recomendado)

Sistemas Operativos:
- Linux (BlueZ)
- Windows 10/11 con adaptador BLE
- macOS 12+

Dependencias Python:
- bleak
- matplotlib
- tkinter (en Linux puede requerir paquete del sistema)

Paquetes del sistema (según plataforma):
- Linux (Debian/Ubuntu sugerido): bluez, libbluetooth-dev, python3-tk

------------------------------------------------------------
INSTALACIÓN
------------------------------------------------------------
1) Clonar el repositorio
   git clone https://github.com/tu-usuario/bluetooth-security-monitor.git
   cd bluetooth-security-monitor

2) Crear y activar entorno virtual
   python -m venv .venv
   # Linux/macOS:
   source .venv/bin/activate
   # Windows:
   .\.venv\Scripts\activate

3) Instalar dependencias
   pip install --upgrade pip
   pip install bleak matplotlib

   (Linux Debian/Ubuntu)
   sudo apt-get update && sudo apt-get install -y python3-tk bluez libbluetooth-dev

------------------------------------------------------------
EJECUCIÓN
------------------------------------------------------------
python main.py
# o el nombre real del archivo si es distinto

Al iniciar, la app:
- Crea (si no existe) bluetooth_security.db
- Realiza limpieza de eventos antiguos (>30 días)
- Comienza el escaneo BLE en un hilo dedicado
- Actualiza la GUI cada segundo

------------------------------------------------------------
PERMISOS Y NOTAS POR PLATAFORMA
------------------------------------------------------------
Linux (BlueZ):
- Comprueba el servicio Bluetooth:
  sudo systemctl status bluetooth
- (Opcional) Escanear sin sudo:
  sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python3))
- Instala Tk si falta:
  sudo apt-get install -y python3-tk

Windows:
- Requiere adaptador BLE y Bluetooth activado.
- Ejecuta desde un terminal con permisos suficientes si hay errores de acceso.

macOS:
- Concede permiso de Bluetooth a la app/terminal (Seguridad y privacidad).
- Si usas Python de Homebrew, asegúrate de tener Tk compatible.

------------------------------------------------------------
USO DE LA INTERFAZ
------------------------------------------------------------
- Dispositivos actuales: lista en vivo con MAC, Nombre y RSSI (dB), ordenados por señal.
- Historial: detecciones/alertas (botones “Actualizar”, “Limpiar alertas antiguas”, “Eliminar todo”).
- Alertas: eventos de tipo alerta_peligro (botón “Eliminar todas”).
- Gráficos: selecciona un dispositivo (MAC o Nombre) y visualiza la tendencia de RSSI.
  Puntos rojos = alerta_peligro, puntos verdes = alerta_cleared.
- Gestión:
  - Fiables: añadir/eliminar MAC y nombre. Los fiabes se excluyen de alertas.
  - Peligrosos: añadir/eliminar MAC/nombre. Si RSSI ≥ −60 dB (por defecto), generan alerta.

------------------------------------------------------------
PARÁMETROS CLAVE (EN EL CÓDIGO)
------------------------------------------------------------
self.alert_threshold_rssi = -70
  - Solo se consideran dispositivos con RSSI ≥ −70 dB.
self.dangerous_threshold_rssi = -60
  - Si un dispositivo está en la lista de “peligrosos” y su RSSI ≥ −60 dB, se genera alerta_peligro.

Ajusta estos valores para afinar sensibilidad/distancia.

------------------------------------------------------------
BASE DE DATOS (SQLite)
------------------------------------------------------------
Archivo: bluetooth_security.db

Tablas:
- trusted_devices(mac_address PK, device_name, first_seen, last_seen, notes)
- dangerous_devices(mac_address PK, device_name, first_seen, last_seen, notes)
- alerts(timestamp, mac_address, device_name, rssi, alert_type)
  * alert_type: deteccion | alerta_peligro | alerta_cleared

La GUI permite limpiar alertas antiguas (con VACUUM), eliminar historial completo o borrar todas las alertas.

------------------------------------------------------------
SOLUCIÓN DE PROBLEMAS
------------------------------------------------------------
“No se detectan dispositivos”:
- Verifica adaptador BLE y que esté activado.
- En Linux: bluetoothctl show / scan on
- Revisa permisos/capacidades (ver sección Linux).

“Error de Tkinter / no arranca GUI”:
- Instala python3-tk (Linux).
- Asegura que hay entorno gráfico y variables DISPLAY correctas.

“Gráfico vacío”:
- Selecciona exactamente la MAC o nombre que aparece en el historial.
- Puede que existan solo detecciones sin alertas; aún así deberían graficarse.

“Acentos/ñ incorrectos”:
- Guarda los .py en UTF-8; usa una consola que soporte UTF-8.

------------------------------------------------------------
CONSIDERACIONES DE SEGURIDAD
------------------------------------------------------------
- Muchas MAC en BLE son aleatorias y rotan. No confíes solo en la MAC para identificación persistente.
- El RSSI NO equivale a distancia exacta; varía por hardware, obstáculos y potencia.
- Uso educativo/laboratorio. Respeta las leyes y políticas locales al escanear.

------------------------------------------------------------
ROADMAP SUGERIDO
------------------------------------------------------------
- Exportar/Importar listas (CSV/JSON).
- Parámetros de escaneo configurables desde la GUI.
- Notificaciones del sistema (tray/toast).
- Filtros por fabricante/UUID de servicio (si disponibles).
- Empaquetado con PyInstaller para binarios standalone.

------------------------------------------------------------
ESTRUCTURA SUGERIDA DEL REPO
------------------------------------------------------------
bluetooth-security-monitor/
├─ README.md
├─ main.py
├─ requirements.txt
├─ bluetooth_security.db        # se crea en runtime (ignorar en git)
├─ docs/
│  └─ img/
│     ├─ current.png
│     ├─ history.png
│     ├─ alerts.png
│     ├─ graphs.png
│     └─ management.png
└─ LICENSE

------------------------------------------------------------
EJEMPLO requirements.txt
------------------------------------------------------------
bleak>=0.22
matplotlib>=3.8

# tkinter se instala vía sistema en Linux (python3-tk); en Windows/macOS viene con la distribución oficial de Python.

------------------------------------------------------------
LICENCIA
------------------------------------------------------------
Este proyecto se distribuye bajo licencia MIT (o la que prefieras). Añade un archivo LICENSE al repositorio.
