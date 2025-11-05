# ⚙️ Carpeta `/config` - Configuración del Sistema

## Descripción General

La carpeta `config/` contiene todos los archivos de configuración del Sistema Anti-Keylogger Unificado. Estos archivos permiten personalizar el comportamiento del sistema, ajustar umbrales de detección, configurar plugins y gestionar listas blancas sin modificar código.

La configuración está distribuida en múltiples archivos para:
- **Modularidad**: Cada aspecto tiene su configuración independiente
- **Mantenibilidad**: Fácil localizar y modificar opciones específicas
- **Seguridad**: Separación de configuraciones sensibles
- **Escalabilidad**: Agregar nuevas configuraciones sin afectar existentes

## 📋 Formato de Archivos

- **TOML** (`*.toml`): Configuración principal del sistema (más legible)
- **JSON** (`*.json`): Configuraciones específicas de plugins y componentes

## 🗂️ Archivos de Configuración

### `unified_config.toml` 🎯
**Propósito**: Configuración principal y global del sistema

**Funcionalidad**:
- Define parámetros globales del antivirus
- Configura comportamiento general del sistema
- Establece límites de recursos
- Controla plugins principales
- Parámetros de rendimiento

**Descripción Técnica**:

Archivo TOML estructurado en secciones que el motor principal (`engine.py`) carga al iniciar. Utiliza formato TOML por su legibilidad superior a JSON para configuración manual.

**Secciones principales**:

#### `[system]`
Configuración global del sistema:
```toml
name = "Sistema Anti-Keylogger Unificado"
version = "2.0.0"
debug_mode = false           # Modo debug (logging verbose)
log_level = "INFO"           # DEBUG, INFO, WARNING, ERROR, CRITICAL
max_log_files = 10           # Archivos de log a mantener
log_rotation_size = "10MB"   # Tamaño antes de rotar log
```

**Uso técnico**: El `UnifiedAntivirusEngine` lee esta sección en `__init__()` para configurar logging global y comportamiento base del sistema.

#### `[detection]`
Parámetros de detección:
```toml
real_time_monitoring = true       # Monitoreo en tiempo real
scan_interval_seconds = 2         # Intervalo entre escaneos
threat_cache_size = 1000          # Caché de amenazas detectadas
auto_quarantine = false           # Cuarentena automática
notification_level = "medium"     # low, medium, high, critical
```

**Uso técnico**: Los detectores consultan estos valores para ajustar su comportamiento. El `scan_interval` controla la frecuencia de análisis en monitores.

#### `[plugins]`
Gestión de plugins:
```toml
auto_discover = true                  # Descubrimiento automático
plugin_timeout_seconds = 30           # Timeout para activación
max_concurrent_plugins = 10           # Plugins simultáneos
plugin_directories = ["plugins"]      # Directorios a escanear
```

**Uso técnico**: El `PluginManager` usa estos valores para:
- Auto-descubrimiento de plugins
- Control de timeouts en activación
- Límites de concurrencia

#### `[detectors.behavior]`
Detector de comportamiento:
```toml
enabled = true
cpu_threshold_percent = 80        # % CPU sospechoso
memory_threshold_mb = 100         # MB RAM sospechoso
process_scan_interval = 2         # Segundos entre escaneos
whitelist_system_processes = true # Usar whitelist
```

**Uso técnico**: `BehaviorDetectorPlugin` lee estos umbrales para determinar qué constituye comportamiento anómalo. Valores ajustables según sensibilidad deseada.

#### `[detectors.ml]`
Detector de Machine Learning:
```toml
enabled = true
model_path = "models/modelo_keylogger_from_datos.onnx"
confidence_threshold = 0.7        # 0.0-1.0 (más alto = más estricto)
batch_size = 32                   # Predicciones por lote
enable_realtime_analysis = true   # Análisis en tiempo real
```

**Uso técnico**: `MLDetectorPlugin` carga el modelo ONNX especificado y usa `confidence_threshold` para filtrar detecciones. El `batch_size` afecta rendimiento vs latencia.

#### `[detectors.network]`
Detector de red:
```toml
enabled = true
monitor_external_connections = true
suspicious_ports = [1337, 4444, 5555, 6666, 7777, 8080, 9999]
connection_timeout_seconds = 30
max_connections_per_ip = 10
```

**Uso técnico**: `NetworkDetectorPlugin` monitorea conexiones contra puertos sospechosos. Lista configurable según inteligencia de amenazas actualizada.

#### `[interfaces.ui]`
Configuración de interfaz:
```toml
enabled = true
window_title = "Sistema Anti-Keylogger Unificado"
window_size = [800, 600]          # [ancho, alto]
update_interval_ms = 1000         # Actualización UI
show_detailed_logs = false
theme = "default"                 # default, dark, light
```

**Uso técnico**: `professional_ui_robust.py` lee estos valores para configurar la ventana tkinter y frecuencia de actualización de widgets.

#### `[quarantine]`
Sistema de cuarentena:
```toml
enabled = true
quarantine_directory = "quarantine"
auto_quarantine_high_risk = false   # Automático para alto riesgo
keep_quarantine_days = 30           # Días antes de limpieza
```

**Uso técnico**: `QuarantineHandlerPlugin` utiliza estos parámetros para gestionar archivos aislados.

#### `[notifications]`
Sistema de notificaciones:
```toml
enabled = true
show_desktop_notifications = true
sound_alerts = false
log_to_file = true
email_alerts = false
```

**Uso técnico**: `AlertManagerPlugin` determina qué canales de notificación activar.

#### `[performance]`
Optimización de rendimiento:
```toml
max_memory_usage_mb = 512
max_cpu_usage_percent = 25
cleanup_interval_minutes = 60
cache_size_mb = 100
```

**Uso técnico**: El motor monitorea estos límites y ajusta comportamiento para no excederlos. Realiza cleanup periódico según `cleanup_interval`.

---

### `alerts_config.json` 🚨
**Propósito**: Configuración del sistema de alertas y notificaciones

**Funcionalidad**:
- Define niveles de severidad de alertas
- Configura acciones por nivel
- Establece límites de notificaciones
- Configura respuestas automáticas

**Descripción Técnica**:

Archivo JSON usado por `AlertManagerPlugin` para determinar cómo responder a diferentes tipos de amenazas detectadas.

**Estructura principal**:

#### `severity_levels`
Define 4 niveles de severidad con sus respuestas:

```json
"low": {
    "color": "#FFD700",              // Amarillo
    "action": "log_only",            // Solo registrar
    "notification": false            // Sin notificación
}
```

```json
"medium": {
    "color": "#FF8C00",              // Naranja
    "action": "log_and_notify",      // Log + notificar
    "notification": true
}
```

```json
"high": {
    "color": "#FF4500",              // Rojo-naranja
    "action": "log_notify_quarantine",
    "notification": true,
    "auto_quarantine": false         // Requiere confirmación
}
```

```json
"critical": {
    "color": "#FF0000",              // Rojo
    "action": "immediate_response",
    "notification": true,
    "auto_quarantine": true,         // Cuarentena automática
    "block_process": false           // Bloquer proceso (deshabilitado)
}
```

**Uso técnico**: Cuando un detector publica un evento `threat_detected` con `risk_level`, el `AlertManagerPlugin` busca en esta configuración la acción apropiada.

#### `notification_settings`
Control de notificaciones:
```json
"desktop_notifications": true,
"sound_alerts": false,
"email_notifications": false,
"webhook_url": null,
"max_notifications_per_minute": 5  // Rate limiting
```

**Uso técnico**: Previene spam de notificaciones con `max_notifications_per_minute`. Soporta webhooks para integración con sistemas externos.

#### `response_actions`
Acciones automáticas:
```json
"quarantine": {
    "enabled": true,
    "backup_original": true,         // Backup antes de cuarentena
    "quarantine_path": "quarantine/"
}
```

```json
"process_termination": {
    "enabled": false,                // Deshabilitado por seguridad
    "confirm_before_kill": true,
    "whitelist_check": true
}
```

```json
"network_blocking": {
    "enabled": false,
    "block_suspicious_ips": false,
    "firewall_integration": false
}
```

**Consideraciones de seguridad**: `process_termination` y `network_blocking` están deshabilitados por defecto para evitar falsos positivos que interrumpan operaciones legítimas.

---

### `ml_config.json` 🤖
**Propósito**: Configuración del sistema de Machine Learning

**Funcionalidad**:
- Define modelos primarios y de respaldo
- Configura extracción de características
- Parámetros de preprocesamiento
- Configuración de entrenamiento (si está habilitado)

**Descripción Técnica**:

Configuración especializada para `MLDetectorPlugin` y `ml_engine.py`. Define pipeline completo de ML desde extracción de features hasta predicción.

**Estructura principal**:

#### `models`
Configuración de modelos:
```json
"primary_model": {
    "name": "keylogger_detector_onnx",
    "path": "models/modelo_keylogger_from_datos.onnx",
    "type": "onnx",
    "enabled": true,
    "confidence_threshold": 0.7,
    "preprocessing": {
        "normalize_features": true,
        "feature_scaling": "standard",  // standard, minmax, robust
        "handle_missing": "mean"        // mean, median, zero
    }
}
```

**Uso técnico**: El `MLEngine` intenta cargar `primary_model` primero. Si falla, utiliza `backup_model` (sklean pickle). El `confidence_threshold` filtra predicciones con baja confianza.

```json
"backup_model": {
    "name": "random_forest_backup",
    "path": "models/rf_large_model_20250918_112442.pkl",
    "type": "pickle",
    "enabled": false,
    "confidence_threshold": 0.6       // Umbral más bajo para backup
}
```

#### `feature_extraction`
Define qué características extraer del sistema:

**Process Features** (características de procesos):
```json
"process_features": {
    "cpu_usage": true,
    "memory_usage": true,
    "network_connections": true,
    "file_operations": true,
    "registry_access": false,        // Windows registry
    "keyboard_hooks": true,          // Crítico para keyloggers
    "window_monitoring": true
}
```

**Behavioral Features** (patrones de comportamiento):
```json
"behavioral_features": {
    "process_creation_rate": true,
    "network_frequency": true,
    "file_modification_patterns": true,
    "memory_access_patterns": true,
    "dll_injection_detection": true  // Técnica común de malware
}
```

**Temporal Features** (características temporales):
```json
"temporal_features": {
    "time_windows": [5, 15, 30, 60],     // Ventanas en segundos
    "sliding_window": true,
    "aggregation_methods": ["mean", "max", "std"]
}
```

**Uso técnico**: El `FeatureExtractor` usa esta configuración para construir vectores de características. Las ventanas temporales permiten detectar patrones que se desarrollan en el tiempo.

#### `training`
Configuración de entrenamiento (normalmente deshabilitado en producción):
```json
"training": {
    "data_collection": {
        "enabled": false,
        "anonymize": true,
        "store_path": "training_data/"
    }
}
```

---

### `plugins_config.json` 🔌
**Propósito**: Configuración específica de plugins

**Funcionalidad**:
- Habilita/deshabilita plugins individuales
- Configuración particular de cada plugin
- Dependencias entre plugins
- Prioridades de ejecución

**Descripción Técnica**:

Configuración granular por plugin. El `PluginManager` lee este archivo para determinar qué plugins activar y con qué configuración.

**Estructura típica**:
```json
{
    "plugins": {
        "ml_detector": {
            "enabled": true,
            "priority": 10,
            "dependencies": [],
            "auto_start": true
        },
        "behavior_detector": {
            "enabled": true,
            "priority": 9,
            "dependencies": ["process_monitor"],
            "auto_start": true
        },
        "keylogger_detector": {
            "enabled": true,
            "priority": 10,
            "dependencies": [],
            "auto_start": true
        }
    }
}
```

**Uso técnico**: 
- `priority`: Orden de activación (mayor primero)
- `dependencies`: Plugins que deben activarse antes
- `auto_start`: Si se activa automáticamente con el sistema

---

### `security_config.json` 🔐
**Propósito**: Configuración de seguridad del sistema

**Funcionalidad**:
- Políticas de seguridad
- Configuración de cifrado
- Validación de integridad
- Control de acceso

**Descripción Técnica**:

Define parámetros de seguridad usados por `security_utils.py` y componentes que manejan datos sensibles.

**Estructura típica**:
```json
{
    "security": {
        "encryption": {
            "enabled": false,
            "algorithm": "AES-256",
            "key_derivation": "PBKDF2"
        },
        "integrity_checks": {
            "enabled": true,
            "verify_plugins": true,
            "verify_config": true
        },
        "sandboxing": {
            "enabled": false,
            "isolation_level": "process"
        }
    }
}
```

---

### `whitelist.json` ✅
**Propósito**: Lista blanca de procesos y directorios confiables

**Funcionalidad**:
- Define procesos que no se deben analizar
- Directorios excluidos de monitoreo
- Excepciones para comportamientos anormales
- Reducción de falsos positivos

**Descripción Técnica**:

Lista blanca usada por `WhitelistManager` del `BehaviorDetector` y otros plugins para excluir procesos conocidos como seguros.

**Estructura principal**:

#### `allowed_processes`
Procesos del sistema y aplicaciones confiables:
```json
"allowed_processes": [
    "chrome.exe",           // Navegadores
    "firefox.exe",
    "msedge.exe",
    "code.exe",             // IDEs
    "notepad.exe",
    "explorer.exe",         // Windows core
    "winlogon.exe",
    "csrss.exe",
    "system",
    "svchost.exe"
]
```

**Uso técnico**: Antes de analizar un proceso, se consulta esta lista. Procesos whitelisted se excluyen o reciben análisis reducido.

#### `trusted_directories`
Directorios seguros (usando variables de entorno):
```json
"trusted_directories": [
    "%ProgramFiles%",
    "%ProgramFiles(x86)%",
    "%Windows%",
    "%System32%",
    "%SysWOW64%"
]
```

**Uso técnico**: Archivos en estos directorios tienen menor probabilidad de ser keyloggers. El sistema expande variables de entorno automáticamente.

#### `monitoring_exceptions`
Excepciones para procesos que pueden tener comportamiento anormal pero son legítimos:
```json
"monitoring_exceptions": {
    "high_cpu_processes": [
        "chrome.exe",       // Pestañas múltiples
        "firefox.exe",
        "code.exe",         // Compilación
        "games.exe",
        "video_editor.exe"
    ]
}
```

**Uso técnico**: Estos procesos pueden usar 100% CPU sin ser sospechosos. El detector de comportamiento ajusta umbrales para ellos.

---

### `safe_profiles.json` 👤
**Propósito**: Perfiles de comportamiento seguro conocido

**Funcionalidad**:
- Define patrones normales de aplicaciones
- Comportamiento esperado por categoría
- Baseline para detección de anomalías

**Descripción Técnica**:

Perfiles de comportamiento que el sistema usa como baseline para comparar actividad actual. Si un proceso se desvía significativamente de su perfil, puede indicar compromiso.

**Estructura típica**:
```json
{
    "profiles": {
        "web_browser": {
            "typical_cpu": "5-30%",
            "typical_memory": "100-500MB",
            "network_activity": "high",
            "file_access": "low",
            "keyboard_hooks": false
        },
        "text_editor": {
            "typical_cpu": "2-10%",
            "typical_memory": "50-200MB",
            "network_activity": "low",
            "file_access": "medium",
            "keyboard_hooks": false
        }
    }
}
```

---

### `ui_settings.json` 🎨
**Propósito**: Configuración de la interfaz de usuario

**Funcionalidad**:
- Preferencias visuales del usuario
- Configuración de widgets
- Presets de configuración
- Estado de la UI entre sesiones

**Descripción Técnica**:

Configuración específica de `professional_ui_robust.py`. Se guarda y carga para mantener preferencias del usuario.

**Estructura típica**:
```json
{
    "window_size": "1200x800",
    "theme": "dark",
    "auto_start": false,
    "max_threats_display": 100,
    "aggregate_duplicates": true,
    "update_interval": 500,
    "presets": {
        "basic": {
            "sensitivity": "low",
            "features": ["behavior"]
        },
        "standard": {
            "sensitivity": "medium",
            "features": ["behavior", "ml"]
        },
        "advanced": {
            "sensitivity": "high",
            "features": ["behavior", "ml", "network"]
        }
    }
}
```

**Uso técnico**: La UI carga estos valores en `__init__()` y los actualiza cuando el usuario cambia preferencias. Los `presets` permiten cambiar configuración completa con un clic.

---

### `logging_config.json` 📝
**Propósito**: Configuración avanzada del sistema de logging

**Funcionalidad**:
- Configura handlers de logging
- Define formatos de log
- Rotación de archivos
- Niveles por módulo

**Descripción Técnica**:

Configuración detallada para el sistema de logging de Python. Usado por `utils/logger.py`.

**Estructura típica**:
```json
{
    "version": 1,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "simple": {
            "format": "%(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/antivirus.log",
            "maxBytes": 10485760,
            "backupCount": 5
        },
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO"
        }
    }
}
```

---

## 🔧 Validación de Configuración

El archivo `config_validator.py` valida todas las configuraciones:

```python
# Ejemplo de uso
from config.config_validator import ConfigValidator

validator = ConfigValidator()
errors = validator.validate_all_configs()

if errors:
    for error in errors:
        print(f"Error: {error}")
```

**Validaciones realizadas**:
- Tipos de datos correctos
- Valores en rangos válidos
- Rutas de archivos existentes
- Dependencias satisfechas
- Formato JSON/TOML válido

---

## 🎯 Mejores Prácticas

1. **No modificar durante ejecución**: Detener el sistema antes de editar configuración
2. **Backup antes de cambios**: Mantener copias de configuraciones funcionales
3. **Validar después de editar**: Usar `config_validator.py`
4. **Documentar cambios**: Comentar modificaciones personalizadas
5. **Usar valores por defecto**: Solo cambiar lo necesario
6. **Testear umbrales**: Ajustar gradualmente sensibilidad de detección

## ⚠️ Configuraciones Críticas

**Configuraciones que afectan seguridad**:
- `auto_quarantine`: Cuarentena automática puede interferir operaciones
- `block_process`: Terminar procesos puede causar inestabilidad
- `whitelist`: Lista incorrecta puede permitir amenazas
- `confidence_threshold`: Muy bajo = muchos falsos positivos

**Configuraciones que afectan rendimiento**:
- `scan_interval_seconds`: Muy bajo = alto uso de CPU
- `max_concurrent_plugins`: Muy alto = saturación de recursos
- `batch_size`: Afecta latencia vs throughput de ML
- `cache_size_mb`: Memoria vs velocidad

## 🔄 Actualización de Configuración en Caliente

Algunos plugins soportan recarga de configuración sin reinicio:

```python
# Desde código
plugin.reload_config()

# Desde Event Bus
event_bus.publish('reload_config', {'plugin': 'ml_detector'}, 'system')
```

---

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
