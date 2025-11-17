# 🔌 Sistema de Plugins del Antivirus

## Descripción General

Sistema modular de plugins que proporciona extensibilidad y escalabilidad al antivirus. Implementa una arquitectura basada en componentes que permite agregar nuevas funcionalidades sin modificar el núcleo del sistema.

## 📁 Estructura de Plugins

```
plugins/
├── detectors/           # Plugins de detección de amenazas
├── monitors/           # Plugins de monitoreo del sistema
├── handlers/           # Plugins de manejo de respuestas
├── shared/            # Recursos compartidos entre plugins
├── backup_configs/    # Configuraciones de respaldo
└── upgrade_intelligence.py  # Sistema de actualización inteligente
```

## 🎯 Tipos de Plugins

### 🔍 **Detectores** (`detectors/`)
Plugins especializados en identificar diferentes tipos de amenazas:

- **[Behavior Detector](./detectors/behavior_detector/README.md)** - Análisis de comportamiento de procesos
- **[Keylogger Detector](./detectors/keylogger_detector/README.md)** - Detección específica de keyloggers
- **[ML Detector](./detectors/ml_detector/README.md)** - Detección basada en Machine Learning
- **[Network Detector](./detectors/network_detector/README.md)** - Análisis de tráfico de red
- **[IAST Detector](./detectors/iast_detector/README.md)** - Análisis interactivo de seguridad de aplicaciones

### 📡 **Monitores** (`monitors/`)
Plugins que vigilan diferentes aspectos del sistema:

- **[File Monitor](./monitors/README.md#file-monitor)** - Monitoreo del sistema de archivos
- **[Network Monitor](./monitors/README.md#network-monitor)** - Monitoreo de conexiones de red
- **[Process Monitor](./monitors/README.md#process-monitor)** - Monitoreo de procesos del sistema

### ⚡ **Manejadores** (`handlers/`)
Plugins que gestionan respuestas y acciones:

- **[Alert Manager](./handlers/README.md#alert-manager)** - Gestión de alertas y notificaciones
- **[Logger Handler](./handlers/README.md#logger-handler)** - Manejo de logs y registros
- **[Quarantine Handler](./handlers/README.md#quarantine-handler)** - Gestión de cuarentena de archivos

## 🏗️ Arquitectura de Plugins

### Patrón Template Method
Todos los plugins heredan de `BasePlugin` que define el ciclo de vida común:

```python
class BasePlugin:
    def initialize(self) -> bool      # Inicialización
    def start(self) -> bool          # Inicio de operación
    def stop(self) -> bool           # Parada del plugin
    def cleanup(self) -> bool        # Limpieza de recursos
    def get_status(self) -> dict     # Estado actual
```

### Sistema de Eventos
Los plugins se comunican a través del Event Bus:

- **Productores**: Monitores y detectores publican eventos
- **Consumidores**: Handlers y otros detectores procesan eventos
- **Desacoplamiento**: Comunicación asíncrona y flexible

## ⚙️ Configuración de Plugins

### Configuración Global
```json
{
  "enabled_plugins": ["behavior_detector", "ml_detector", "network_detector"],
  "detector_settings": {
    "sensitivity": "medium",
    "real_time": true
  },
  "monitor_settings": {
    "scan_interval": 1000,
    "deep_scan": false
  }
}
```

### Configuración Individual
Cada plugin tiene su propio `config.json` con configuraciones específicas.

## 🚀 Sistema de Carga Dinámica

### Auto-descubrimiento
El sistema automáticamente:
1. Escanea las carpetas de plugins
2. Detecta plugins válidos
3. Carga configuraciones
4. Inicializa plugins habilitados
5. Establece comunicación entre componentes

### Registro Automático
```python
# Ejecutado por register_plugins.py
plugin_manager.discover_plugins()
plugin_manager.load_plugins()
plugin_manager.start_enabled_plugins()
```

## 📊 Monitoreo y Métricas

### Estado de Plugins
- **Activo/Inactivo**: Estado de ejecución
- **Métricas de rendimiento**: CPU, memoria, eventos procesados
- **Logs individuales**: Cada plugin mantiene sus propios logs
- **Eventos generados**: Contador de eventos publicados

### Dashboard de Plugins
Acceso a través de la UI principal para:
- Ver estado en tiempo real
- Habilitar/deshabilitar plugins
- Configurar parámetros
- Ver métricas de rendimiento

## 🔧 Desarrollo de Nuevos Plugins

### Estructura Mínima
```
new_plugin/
├── __init__.py
├── plugin.py           # Clase principal del plugin
├── config.json         # Configuración por defecto
└── README.md          # Documentación del plugin
```

### Ejemplo Básico
```python
from core.base_plugin import BasePlugin

class NewPlugin(BasePlugin):
    def initialize(self):
        self.load_config()
        return True
    
    def start(self):
        # Lógica de inicio
        return True
```

## 🔄 Sistema de Actualización

### Upgrade Intelligence
El archivo `upgrade_intelligence.py` proporciona:
- Actualizaciones automáticas de plugins
- Migración de configuraciones
- Compatibilidad hacia atrás
- Rollback en caso de errores

## 📝 Logs y Debugging

### Logs por Plugin
Cada plugin mantiene logs separados en:
- `logs/[plugin_name].log`
- Niveles: DEBUG, INFO, WARNING, ERROR, CRITICAL

### Debug Mode
Ejecutar con `--debug` para:
- Logs detallados de cada plugin
- Métricas de rendimiento
- Trazas de eventos entre plugins

## 🤝 Integración con el Core

### Event Bus
Comunicación centralizada:
```python
# Publicar evento
event_bus.publish('threat.detected', threat_data)

# Suscribirse a eventos
event_bus.subscribe('file.modified', self.on_file_change)
```

### Plugin Manager
Gestión centralizada:
- Carga y descarga dinámica
- Resolución de dependencias
- Gestión del ciclo de vida
- Monitoreo de salud

## 📋 Enlaces Relacionados

- **[Core Engine](../core/README.md)** - Motor principal del sistema
- **[Configuración](../config/README.md)** - configuraciones del sistema
- **[Tests de Plugins](../tests/README.md)** - pruebas de los plugins
- **[Documentación Técnica](../doc/COMO_FUNCIONA_TECHNICAL_README.md)** - funcionamiento interno

---

**Nota**: Para desarrollar nuevos plugins, consulta la documentación del core y los ejemplos existentes en cada categoría de plugin.