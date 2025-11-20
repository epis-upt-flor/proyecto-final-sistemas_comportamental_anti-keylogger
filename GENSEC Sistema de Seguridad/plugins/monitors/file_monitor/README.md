# 📁 File Monitor Plugin

## Descripción General

Plugin de monitoreo continuo del sistema de archivos que vigila la creación, modificación y eliminación de archivos en tiempo real, enfocado en detectar actividad maliciosa relacionada con keyloggers y malware.

## 🎯 Funcionalidades Principales

### ✅ **Monitoreo de Archivos**
- **Creación de archivos**: Detección instantánea de nuevos archivos
- **Modificación**: Seguimiento de cambios en archivos existentes
- **Eliminación**: Registro de archivos borrados
- **Renombrado**: Detección de cambios de nombre de archivos

### 📊 **Análisis de Patrones**
- **Archivos de log**: Detección de archivos típicos de keyloggers (*.keylog, *.dat)
- **Ubicaciones sospechosas**: Monitoreo de directorios temporales y ocultos
- **Extensiones peligrosas**: Archivos ejecutables en ubicaciones inusuales
- **Archivos de credenciales**: Detección de archivos de passwords y tokens

### 🔍 **Detección Especializada**
- **Logs de keyloggers**: Patrones específicos de archivos de captura
- **Archivos de configuración maliciosos**: Configs de malware
- **Dumps de memoria**: Archivos de volcado sospechosos
- **Screenshots automáticos**: Capturas de pantalla no autorizadas

## 📁 Archivos del Plugin

```
file_monitor/
├── plugin.py          # FileMonitorPlugin principal
├── test_plugin.py     # Tests unitarios
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "monitor_config": {
    "watch_directories": [
      "%USERPROFILE%\\Documents",
      "%APPDATA%",
      "%TEMP%",
      "%LOCALAPPDATA%\\Temp"
    ],
    "recursive_monitoring": true,
    "real_time_alerts": true,
    "buffer_size": 8192
  },
  "file_patterns": {
    "keylogger_logs": [
      ".*keylog.*\\.(txt|dat|log)$",
      ".*passwords?\\.(txt|log)$",
      ".*credentials\\.(txt|dat)$",
      ".*clipboard\\.(txt|log)$"
    ],
    "suspicious_executables": [
      ".*\\.(exe|scr|com|bat|cmd)$"
    ],
    "screenshot_patterns": [
      ".*screenshot.*\\.(png|jpg|bmp)$",
      ".*capture.*\\.(png|jpg)$"
    ]
  },
  "filtering": {
    "ignore_system_files": true,
    "min_file_size": 100,
    "exclude_extensions": [".tmp", ".log", ".cache"],
    "whitelist_processes": ["notepad.exe", "explorer.exe"]
  }
}
```

### Directorios Monitoreados por Defecto
- **`%USERPROFILE%\\Documents`**: Documentos del usuario
- **`%APPDATA%`**: Datos de aplicaciones
- **`%TEMP%`**: Archivos temporales del sistema
- **`%LOCALAPPDATA%\\Temp`**: Archivos temporales del usuario
- **Desktop**: Escritorio del usuario
- **Downloads**: Carpeta de descargas

## 🔌 **Eventos del Sistema**

### **Eventos Publicados:**
- `file_created` - Nuevo archivo detectado
- `file_modified` - Archivo modificado
- `file_deleted` - Archivo eliminado
- `suspicious_file_detected` - Archivo con patrones sospechosos
- `keylogger_log_detected` - Log de keylogger identificado
- `credentials_file_detected` - Archivo de credenciales encontrado

### **Estructura de Eventos:**
```python
{
  "event_type": "keylogger_log_detected",
  "timestamp": "2024-11-08T15:30:45",
  "file_info": {
    "path": "C:\\Temp\\keylog.txt",
    "size_bytes": 2048,
    "created": "2024-11-08T15:25:00",
    "modified": "2024-11-08T15:30:40",
    "extension": ".txt",
    "hidden": false,
    "readonly": false
  },
  "risk_indicators": [
    "keylogger_pattern_match",
    "suspicious_location",
    "recent_creation"
  ],
  "content_analysis": {
    "contains_keystrokes": true,
    "contains_passwords": true,
    "encoding": "utf-8",
    "entropy": 0.75
  }
}
```

## 🚀 **Uso del Plugin**

### Inicialización Automática
```python
# El plugin se registra automáticamente
# Se activa con la categoría 'monitors'
engine.activate_category('monitors')
```

### Configuración Manual
```python
# Crear instancia del monitor
file_monitor = FileMonitorPlugin()

# Configurar directorios a monitorear
config = {
    "watch_directories": ["C:\\Users\\test", "C:\\Temp"],
    "recursive_monitoring": True
}
file_monitor.configure(config)

# Inicializar y comenzar monitoreo
if file_monitor.initialize():
    file_monitor.start()
```

## 📈 **Métricas y Estadísticas**

### Métricas del Monitor
```python
monitor_stats = {
    'files_monitored': 0,           # Archivos bajo monitoreo
    'events_generated': 0,          # Total de eventos generados
    'suspicious_files_found': 0,    # Archivos sospechosos detectados
    'keylogger_logs_detected': 0,   # Logs de keylogger encontrados
    'false_positives': 0,           # Falsos positivos reportados
    'directories_watched': 0,       # Directorios monitoreados
    'uptime_hours': 0.0            # Tiempo de funcionamiento
}
```

### Performance del Monitor
- **Latencia de detección**: < 100ms para nuevos archivos
- **Uso de memoria**: < 30MB por directorio monitoreado
- **Impacto en CPU**: < 1% en operaciones normales de archivos
- **Throughput**: >1000 eventos/segundo en picos de actividad

## 🔬 **Análisis Especializado de Keyloggers**

### Patrones de Archivos de Keyloggers
```python
keylogger_file_patterns = {
    'log_files': [
        r'.*keylog.*\.(txt|dat|log)$',      # Logs generales
        r'.*readme\.txt$',                   # Harem.c style
        r'.*text.*data.*\.txt$',            # Ghost_Writer style
        r'.*clipboard.*\.txt$',             # Clipboard logs
        r'.*syseminfo\.txt$'                # System info logs
    ],
    'screenshot_files': [
        r'.*screenshot.*\.(png|jpg|bmp)$',  # Screenshots
        r'.*capture.*\.(png|jpg)$',         # Screen captures
        r'.*screen.*\.(png|jpg)$'           # Screen dumps
    ],
    'encrypted_logs': [
        r'.*\.enc$',                        # Encrypted files
        r'.*\.dat$',                        # Binary data
        r'.*\.key$'                         # Key files
    ]
}
```

### Análisis de Contenido
El monitor realiza análisis superficial del contenido para detectar:
- **Secuencias de teclas**: Patrones típicos de keystrokes capturados
- **Passwords**: Strings que parecen contraseñas
- **URLs**: Direcciones web capturadas
- **Emails**: Direcciones de correo en logs
- **Timestamps**: Marcas de tiempo regulares (indicador de logging)

## 🛡️ **Detección Avanzada**

### Análisis de Entropía
```python
def analyze_file_entropy(file_path):
    # Calcula entropía para detectar archivos encriptados
    # Keyloggers a menudo encriptan sus logs
    entropy = calculate_entropy(file_content)
    
    if entropy > 0.8:  # Alta entropía = posible encriptación
        return "encrypted_content"
    elif entropy < 0.3:  # Baja entropía = texto repetitivo
        return "repetitive_content"
    else:
        return "normal_content"
```

### Análisis Temporal
- **Frecuencia de escritura**: Keyloggers escriben frecuentemente
- **Horarios de actividad**: Actividad fuera de horarios normales
- **Patrones regulares**: Escrituras cada X segundos (beacons)
- **Correlación con actividad del usuario**: Writes correlacionados con input

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Ejecutar tests unitarios
python test_plugin.py

# Test manual del plugin  
cd plugins/monitors/file_monitor
python plugin.py --test

# Crear archivos de prueba
python plugin.py --create-test-files

# Simular actividad de keylogger
python plugin.py --simulate-keylogger
```

### Debugging y Análisis
```python
# Habilitar logging detallado
import logging
logging.basicConfig(level=logging.DEBUG)

# Análisis de un archivo específico
file_monitor.analyze_file("C:\\Temp\\suspicious.txt")

# Verificar patrones de detección
file_monitor.check_file_patterns("keylog.txt")

# Estadísticas en tiempo real
stats = file_monitor.get_statistics()
print(f"Files monitored: {stats['files_monitored']}")
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **Alto Consumo de Recursos**
```
Causa: Monitoreo de directorios muy grandes o activos
Solución: 
- Reducir directorios monitoreados
- Aumentar filtros de exclusión
- Usar monitoring no-recursivo en directorios grandes
```

#### **Muchos Falsos Positivos**
```
Causa: Patrones de detección muy amplios
Solución:
- Refinar expresiones regulares
- Agregar más extensiones a whitelist
- Aumentar min_file_size para filtrar archivos pequeños
```

#### **Eventos Perdidos**
```
Causa: Buffer overflow o alta latencia del sistema
Solución:
- Aumentar buffer_size
- Reducir directorios monitoreados
- Optimizar procesamiento de eventos
```

### Optimización de Performance
- **Filtrado temprano**: Aplicar filtros antes del análisis completo
- **Async processing**: Procesar eventos en threads separados
- **Cache de patrones**: Compilar regex una sola vez
- **Batch processing**: Procesar múltiples eventos juntos

## 📚 **Integración con Detectores**

### Flujo de Análisis
1. **File Monitor** detecta nuevo archivo
2. **Análisis de patrones**: Verifica si coincide con patrones sospechosos
3. **Event Bus**: Distribuye evento según tipo detectado
4. **Detectores especializados** analizan:
   - **Keylogger Detector**: Analiza si es log de keylogger
   - **Behavior Detector**: Correlaciona con actividad de procesos
   - **Network Detector**: Verifica si hay exfiltración asociada

### Correlación Multi-Monitor
```python
# Correlación entre file y process monitor
correlation_data = {
    'file_event': file_event,
    'related_process': process_info,
    'temporal_correlation': time_diff < 5,  # 5 segundos
    'spatial_correlation': same_directory
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[👁️ Sistema de Monitores](../README.md)** - Documentación de monitores
- **[🖥️ Process Monitor](../process_monitor/README.md)** - Monitor de procesos
- **[🌐 Network Monitor](../network_monitor/README.md)** - Monitor de red
- **[⌨️ Keylogger Detector](../../detectors/keylogger_detector/README.md)** - Detección de keyloggers
- **[🎯 Behavior Detector](../../detectors/behavior_detector/README.md)** - Análisis de comportamiento
- **[📊 Core Engine](../../../core/README.md)** - Event Bus y motor principal
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración
- **[📝 Logs](../../../logs/README.md)** - Sistema de logging

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Vigilancia Continua del Sistema de Archivos**