# 👁️ Carpeta `/plugins/monitors` - Monitores del Sistema

## Descripción General

La carpeta `plugins/monitors/` contiene los plugins de **monitoreo continuo** del sistema que capturan datos en tiempo real sobre procesos, archivos y red. Estos monitores son la **primera línea de defensa**, alimentando datos a los detectores para análisis.

Los monitores implementan `MonitorInterface` y operan en threads separados publicando eventos periódicamente al Event Bus cuando detectan actividad relevante.

## 🎯 Filosofía de Monitoreo

- **No invasivo**: Observación sin afectar rendimiento del sistema
- **Continuo**: Monitoreo 24/7 en tiempo real
- **Selectivo**: Filtrado inteligente de eventos relevantes
- **Asíncrono**: Threading para no bloquear el sistema

## 📁 Estructura de Monitores

```
plugins/monitors/
├── process_monitor/    # Monitoreo de procesos
│   ├── __init__.py
│   ├── plugin.py
│   ├── test_plugin.py
│   └── config.json
│
├── file_monitor/       # Monitoreo del sistema de archivos
│   ├── __init__.py
│   ├── plugin.py
│   ├── test_plugin.py
│   └── config.json
│
└── network_monitor/    # Monitoreo de red
    ├── __init__.py
    ├── plugin.py
    ├── test_plugin.py
    └── config.json
```

---

## 🖥️ Process Monitor - Monitoreo de Procesos

### `plugin.py`
**Propósito**: Vigilancia continua de procesos del sistema

**Funcionalidad**:
- Detecta creación de nuevos procesos
- Monitorea uso de recursos (CPU, RAM)
- Rastrea jerarquía de procesos (padre-hijo)
- Identifica nombres y rutas sospechosos
- Publica eventos cuando detecta anomalías

**Descripción Técnica**:

**Clase Principal**: `ProcessMonitorPlugin`

**Atributos**:
```python
is_monitoring: bool
monitor_thread: threading.Thread
known_processes: Set[int]           # PIDs conocidos
process_history: List[Dict]         # Historial de procesos
suspicious_patterns: List[str]      # Patrones sospechosos
```

**Configuración** (`config.json`):
```json
{
    "update_interval": 2.0,          // Segundos entre escaneos
    "cpu_threshold": 80.0,           // % CPU sospechoso
    "memory_threshold": 1073741824,  // 1GB RAM sospechoso
    "check_new_processes": true,
    "check_resource_usage": true,
    "check_suspicious_names": true
}
```

**Métodos clave**:

1. **`start_monitoring()`**:
   ```python
   # Inicia thread de monitoreo continuo
   # Captura snapshot inicial de procesos
   # Loop infinito con intervalo configurable
   ```

2. **`_monitor_processes_loop()`**:
   ```python
   while self.is_monitoring:
       current_processes = psutil.process_iter()
       
       # Detectar nuevos procesos
       new_pids = current_pids - self.known_processes
       for pid in new_pids:
           self._handle_new_process(process)
       
       # Verificar recursos
       for proc in current_processes:
           if proc.cpu_percent() > threshold:
               self._publish_high_cpu_alert(proc)
       
       time.sleep(self.update_interval)
   ```

3. **`_handle_new_process(process)`**:
   ```python
   # Extraer información del proceso
   info = {
       'pid': process.pid,
       'name': process.name(),
       'exe': process.exe(),
       'cmdline': process.cmdline(),
       'parent': process.parent(),
       'cpu_percent': process.cpu_percent(),
       'memory_info': process.memory_info()
   }
   
   # Verificar patrones sospechosos
   if self._is_suspicious_name(info['name']):
       event_bus.publish('suspicious_process_detected', info)
   
   # Publicar evento general
   event_bus.publish('new_process_detected', info)
   ```

**Eventos publicados**:
- `new_process_detected`: Nuevo proceso iniciado
- `suspicious_process_detected`: Proceso con nombre sospechoso
- `high_cpu_process`: Proceso con alto uso de CPU
- `high_memory_process`: Proceso con alto uso de RAM
- `process_terminated`: Proceso terminado

**Patrones sospechosos**:
```python
suspicious_patterns = [
    'keylog', 'keycap', 'spyware', 'trojan', 
    'backdoor', 'stealer', 'logger', 'capture',
    'hook', 'inject', 'rat', 'bot'
]
```

---

## 📂 File Monitor - Monitoreo del Sistema de Archivos

### `plugin.py`
**Propósito**: Vigilancia de cambios en archivos y directorios

**Funcionalidad**:
- Monitorea directorios críticos (Documents, Desktop, AppData, Temp)
- Detecta creación de archivos sospechosos
- Rastrea modificaciones y eliminaciones
- Identifica extensiones peligrosas
- Calcula hashes de archivos

**Descripción Técnica**:

**Clase Principal**: `FileSystemMonitorPlugin`

Utiliza la librería **watchdog** para monitoreo eficiente del sistema de archivos.

**Componentes**:
```python
observer: Observer                  # watchdog Observer
event_handler: FileSystemEventHandler
file_events: List[Dict]
file_hashes: Dict[str, str]        # path -> hash
```

**Configuración** (`config.json`):
```json
{
    "watch_directories": [
        "%USERPROFILE%\\Documents",
        "%USERPROFILE%\\Desktop",
        "%APPDATA%",
        "C:\\Windows\\Temp"
    ],
    "suspicious_extensions": [
        ".exe", ".dll", ".bat", ".cmd", ".scr",
        ".vbs", ".js", ".jar", ".com"
    ],
    "keylogger_patterns": [
        "keylog", "capture", "hook", "spy", "stealer"
    ],
    "max_file_size_mb": 100,
    "track_file_hashes": true,
    "alert_threshold_events_per_minute": 50
}
```

**Métodos clave**:

1. **`start_monitoring()`**:
   ```python
   # Crear Observer de watchdog
   self.observer = Observer()
   
   # Registrar handlers para cada directorio
   for directory in self.watch_directories:
       self.observer.schedule(
           self.event_handler,
           directory,
           recursive=True
       )
   
   # Iniciar observación
   self.observer.start()
   ```

2. **`_handle_file_event(event_type, file_path)`**:
   ```python
   # Filtrar eventos irrelevantes
   if not self._is_relevant_file(file_path):
       return
   
   # Extraer información
   info = {
       'event_type': event_type,  # created, modified, deleted
       'file_path': file_path,
       'file_name': os.path.basename(file_path),
       'timestamp': datetime.now(),
       'file_size': os.path.getsize(file_path)
   }
   
   # Verificar patrones sospechosos
   if self._matches_suspicious_pattern(file_path):
       info['suspicious'] = True
       event_bus.publish('suspicious_file_detected', info)
   
   # Calcular hash si está habilitado
   if self.track_file_hashes:
       info['sha256'] = self._calculate_file_hash(file_path)
   
   event_bus.publish('file_activity_detected', info)
   ```

3. **`_matches_suspicious_pattern(file_path)`**:
   ```python
   filename = os.path.basename(file_path).lower()
   extension = os.path.splitext(file_path)[1].lower()
   
   # Verificar extensión sospechosa
   if extension in self.suspicious_extensions:
       return True
   
   # Verificar patrones de keylogger
   for pattern in self.keylogger_patterns:
       if pattern in filename:
           return True
   
   return False
   ```

**Eventos publicados**:
- `file_activity_detected`: Actividad general de archivos
- `suspicious_file_detected`: Archivo con características sospechosas
- `high_activity_directory`: Directorio con actividad anormal
- `large_file_created`: Archivo grande creado

**Características técnicas**:
- **Watchdog**: Eventos del sistema operativo en tiempo real
- **Recursive**: Monitoreo recursivo de subdirectorios
- **Hashing**: SHA256 para integridad de archivos
- **Rate limiting**: Control de eventos por minuto

---

## 🌐 Network Monitor - Monitoreo de Red

### `plugin.py`
**Propósito**: Vigilancia de conexiones de red del sistema

**Funcionalidad**:
- Captura conexiones activas (TCP/UDP)
- Monitorea puertos sospechosos
- Rastrea conexiones por proceso
- Detecta conexiones externas
- Calcula estadísticas de tráfico

**Descripción Técnica**:

**Clase Principal**: `NetworkMonitorPlugin`

Utiliza **psutil** para acceder a conexiones de red del sistema.

**Atributos**:
```python
is_monitoring: bool
monitor_thread: threading.Thread
connection_history: Dict[tuple, Dict]  # (ip, port, proto) -> stats
suspicious_ports: List[int]
known_good_ips: Set[str]
```

**Configuración** (`config.json`):
```json
{
    "update_interval": 5.0,
    "monitor_tcp": true,
    "monitor_udp": true,
    "suspicious_ports": [
        1337, 4444, 5555, 6666, 7777, 8080, 9999
    ],
    "monitor_external_only": true,
    "max_connections_per_process": 50,
    "track_bandwidth": true
}
```

**Métodos clave**:

1. **`start_monitoring()`**:
   ```python
   # Iniciar thread de monitoreo
   self.monitor_thread = threading.Thread(
       target=self._monitor_network_loop,
       daemon=True
   )
   self.monitor_thread.start()
   ```

2. **`_monitor_network_loop()`**:
   ```python
   while self.is_monitoring:
       # Capturar conexiones activas
       connections = psutil.net_connections(kind='inet')
       
       # Procesar cada conexión
       for conn in connections:
           conn_info = self._process_connection(conn)
           
           # Verificar si es sospechosa
           if self._is_suspicious_connection(conn_info):
               event_bus.publish('suspicious_connection', conn_info)
           else:
               event_bus.publish('network_connection', conn_info)
       
       time.sleep(self.update_interval)
   ```

3. **`_process_connection(conn)`**:
   ```python
   # Obtener información del proceso asociado
   try:
       process = psutil.Process(conn.pid)
       process_name = process.name()
       process_exe = process.exe()
   except:
       process_name = "Unknown"
       process_exe = None
   
   # Construir información de conexión
   info = {
       'local_addr': conn.laddr,
       'remote_addr': conn.raddr,
       'status': conn.status,
       'pid': conn.pid,
       'process_name': process_name,
       'process_exe': process_exe,
       'protocol': 'TCP' if conn.type == 1 else 'UDP'
   }
   
   # Actualizar estadísticas
   self._update_connection_stats(info)
   
   return info
   ```

4. **`_is_suspicious_connection(conn_info)`**:
   ```python
   # Puerto sospechoso
   if conn_info.get('remote_addr'):
       port = conn_info['remote_addr'][1]
       if port in self.suspicious_ports:
           return True
   
   # Conexión a IP maliciosa conocida
   ip = conn_info['remote_addr'][0]
   if self._is_malicious_ip(ip):
       return True
   
   # Demasiadas conexiones del mismo proceso
   if self._exceeds_connection_limit(conn_info['pid']):
       return True
   
   return False
   ```

**Eventos publicados**:
- `network_connection`: Conexión de red detectada
- `suspicious_connection`: Conexión sospechosa
- `high_bandwidth_process`: Proceso con alto uso de ancho de banda
- `connection_to_malicious_ip`: Conexión a IP conocida maliciosa
- `unusual_port_activity`: Actividad en puerto inusual

**Características técnicas**:
- **Real-time**: Captura en tiempo real con psutil
- **Process correlation**: Asocia conexiones con procesos
- **Statistics tracking**: Bandwidth, connection count
- **Threat intel**: Verificación contra IPs maliciosas

---

## 🔄 Flujo de Monitoreo

```
┌─────────────────────────────────────────────────────┐
│              Sistema Operativo                      │
│  (Procesos, Archivos, Conexiones de Red)           │
└────────────────┬────────────────────────────────────┘
                 │
      ┌──────────┼──────────┐
      │          │           │
      ▼          ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ Process  │ │   File   │ │ Network  │
│ Monitor  │ │ Monitor  │ │ Monitor  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │
     └────────────┴────────────┘
                  │
                  ▼
          ┌───────────────┐
          │   Event Bus   │
          │ (data events) │
          └───────┬───────┘
                  │
      ┌───────────┴───────────┐
      │                       │
      ▼                       ▼
┌───────────┐         ┌───────────────┐
│ Detectors │         │ UI Dashboard  │
│ (Analyze) │         │ (Visualize)   │
└───────────┘         └───────────────┘
```

## 📊 Métricas de Monitores

Cada monitor recopila métricas:

```python
stats = {
    'monitoring_start_time': datetime,
    'total_events_captured': int,
    'events_published': int,
    'suspicious_events': int,
    'monitoring_uptime_seconds': float,
    'avg_event_processing_time_ms': float
}
```

## ⚙️ Configuración de Monitores

**Ajustes comunes**:
- `update_interval`: Balance entre detalle y rendimiento
- `thresholds`: Umbrales de alerta (CPU, memoria, eventos)
- `filters`: Qué monitorear y qué ignorar
- `directories/ports`: Objetivos específicos del monitoreo

## 🧪 Testing de Monitores

```python
# Test Process Monitor
from plugins.monitors.process_monitor.plugin import ProcessMonitorPlugin

monitor = ProcessMonitorPlugin('process_monitor', '1.0')
monitor.initialize()
monitor.start_monitoring()

# Verificar que captura procesos
time.sleep(5)
assert monitor.stats['events_published'] > 0

monitor.stop_monitoring()
```

## 💡 Mejores Prácticas

1. **Intervalo de actualización**: 2-5 segundos es óptimo
2. **Filtrado inteligente**: No publicar eventos triviales
3. **Resource-aware**: Ajustar frecuencia según carga del sistema
4. **Error handling**: Continuar monitoreando ante errores
5. **Cleanup**: Liberar recursos al detener monitor

## ⚠️ Consideraciones

- **Rendimiento**: Monitoreo continuo consume recursos
- **Permisos**: Algunos monitores requieren privilegios elevados
- **Privacy**: Respetar privacidad del usuario
- **Storage**: Historial de eventos puede crecer

---

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
