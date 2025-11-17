# 🖥️ Process Monitor Plugin

## Descripción General

Plugin de monitoreo continuo que vigila la actividad de procesos en tiempo real, detectando nuevos procesos, cambios en el uso de recursos y patrones de comportamiento sospechosos.

## 🎯 Funcionalidades Principales

### ✅ **Monitoreo Continuo**
- **Nuevos procesos**: Detección instantánea de procesos creados
- **Procesos terminados**: Seguimiento de procesos que finalizan
- **Jerarquía de procesos**: Relación padre-hijo de procesos
- **Cambios de estado**: Monitoreo de estados (running, stopped, zombie)

### 📊 **Análisis de Recursos**
- **Uso de CPU**: Monitoreo de porcentaje de CPU por proceso
- **Consumo de memoria**: RAM utilizada por cada proceso
- **Handles abiertos**: Archivos, sockets y handles del sistema
- **Threads activos**: Número de hilos por proceso

### 🔍 **Detección de Anomalías**
- **Nombres sospechosos**: Patrones de nombres típicos de malware
- **Ubicaciones inusuales**: Procesos ejecutándose desde ubicaciones atípicas
- **Consumo anómalo**: Uso de recursos fuera de lo normal
- **Comportamiento furtivo**: Procesos que intentan ocultarse

## 📁 Archivos del Plugin

```
process_monitor/
├── plugin.py          # ProcessMonitorPlugin principal
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "monitor_config": {
    "update_interval": 2.0,
    "cpu_threshold": 80.0,
    "memory_threshold_mb": 1024,
    "enable_process_tracking": true,
    "enable_resource_monitoring": true
  },
  "detection_patterns": {
    "suspicious_names": [".*keylog.*", ".*stealer.*", ".*hack.*"],
    "suspicious_locations": ["%TEMP%", "%APPDATA%\\\\Local\\\\Temp"],
    "trusted_directories": ["%PROGRAMFILES%", "%WINDIR%"]
  },
  "filtering": {
    "ignore_system_processes": true,
    "min_runtime_seconds": 5,
    "whitelist_enabled": true
  }
}
```

### Parámetros Clave
- **`update_interval`**: Frecuencia de escaneo (segundos)
- **`cpu_threshold`**: Umbral de CPU sospechoso (%)
- **`memory_threshold_mb`**: Umbral de memoria sospechosa (MB)
- **`suspicious_names`**: Patrones regex de nombres sospechosos
- **`trusted_directories`**: Directorios considerados seguros

## 🔌 **Eventos del Sistema**

### **Eventos Publicados:**
- `process_created` - Nuevo proceso detectado
- `process_terminated` - Proceso terminado
- `high_cpu_usage` - Uso de CPU anómalo detectado
- `high_memory_usage` - Consumo de memoria excesivo
- `suspicious_process_detected` - Proceso con características sospechosas
- `process_hierarchy_changed` - Cambios en jerarquía de procesos

### **Estructura de Eventos:**
```python
{
  "event_type": "process_created",
  "timestamp": "2024-11-08T15:30:45",
  "process_info": {
    "pid": 1234,
    "name": "suspicious_app.exe", 
    "path": "C:\\Temp\\suspicious_app.exe",
    "parent_pid": 4567,
    "cpu_percent": 25.5,
    "memory_mb": 128,
    "threads": 3,
    "handles": 45
  },
  "risk_indicators": [
    "suspicious_location",
    "high_cpu_usage"
  ]
}
```

## 🚀 **Uso del Plugin**

### Inicialización Automática
```python
# El plugin se registra automáticamente
# Se activa con la categoría 'monitors'
engine.activate_category('monitors')
```

### Uso Manual
```python
# Crear instancia del monitor
process_monitor = ProcessMonitorPlugin()

# Configurar el monitor
process_monitor.configure(config_data)

# Inicializar y comenzar monitoreo
if process_monitor.initialize():
    process_monitor.start()
    
# Obtener procesos actuales
processes = process_monitor.get_current_processes()
```

## 📈 **Métricas y Estadísticas**

### Métricas del Monitor
```python
monitor_stats = {
    'processes_monitored': 0,      # Total de procesos monitoreados
    'new_processes_detected': 0,   # Nuevos procesos detectados
    'suspicious_processes': 0,      # Procesos sospechosos encontrados
    'high_cpu_alerts': 0,          # Alertas de CPU alto
    'high_memory_alerts': 0,       # Alertas de memoria alta
    'uptime_hours': 0.0            # Tiempo de funcionamiento
}
```

### Performance del Monitor
- **Tiempo de escaneo**: < 500ms por ciclo
- **Uso de memoria**: < 50MB
- **Impacto en CPU**: < 2% en promedio
- **Procesos por ciclo**: 100-500 procesos típicamente

## 🔬 **Análisis Especializado**

### Detección de Keyloggers
El monitor está optimizado para detectar keyloggers:

```python
keylogger_indicators = {
    'suspicious_apis': ['SetWindowsHookEx', 'GetAsyncKeyState'],
    'typical_names': ['keylog', 'logger', 'capture', 'hook'],
    'stealth_behavior': ['low_cpu_high_activity', 'hidden_window'],
    'file_patterns': ['*.keylog', '*.dat', 'passwords.txt']
}
```

### Análisis de Comportamiento
- **Patrón de recursos**: Keyloggers típicamente usan poca CPU pero constante
- **Ubicación furtiva**: Suelen ejecutarse desde directorios temporales
- **Persistencia**: Intentan mantenerse ejecutándose continuamente
- **Comunicación**: Algunos envían datos a servidores remotos

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Ejecutar tests unitarios
python -m pytest process_monitor/

# Test manual del plugin
cd plugins/monitors/process_monitor
python plugin.py --test

# Simulación de procesos sospechosos
python plugin.py --simulate-suspicious
```

### Debugging
```python
# Habilitar logging detallado
import logging
logging.basicConfig(level=logging.DEBUG)

# Test de un proceso específico
process_monitor.analyze_process(pid=1234)

# Verificar patrones de detección
process_monitor.check_suspicious_patterns("suspicious_app.exe")
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **High CPU Usage del Monitor**
```
Causa: Intervalo de actualización muy bajo
Solución: Aumentar update_interval a 3-5 segundos
```

#### **Falsos Positivos**
```
Causa: Patrones de detección muy amplios
Solución: Refinar suspicious_names y agregar whitelist
```

#### **Procesos No Detectados**
```
Causa: Permisos insuficientes o filtros muy restrictivos
Solución: Ejecutar como administrador y revisar filtros
```

### Optimización
- **Filtrado inteligente**: Usar whitelist para procesos conocidos
- **Sampling adaptativo**: Reducir frecuencia si no hay actividad
- **Cache de procesos**: Evitar re-análisis de procesos conocidos
- **Lazy loading**: Cargar detalles solo cuando es necesario

## 📚 **Integración con Detectores**

### Flujo de Datos
1. **Process Monitor** detecta nuevo proceso
2. **Event Bus** distribuye evento `process_created`
3. **Detectores** analizan datos del proceso:
   - **Behavior Detector**: Analiza patrones de comportamiento
   - **Keylogger Detector**: Busca características de keyloggers
   - **ML Detector**: Ejecuta predicción si hay datos de red
4. **Handlers** procesan amenazas detectadas

### Correlación de Datos
```python
# El monitor etiqueta procesos para correlación
process_data = {
    'monitor_timestamp': timestamp,
    'correlation_id': uuid4(),
    'source_monitor': 'process_monitor',
    'process_info': detailed_info
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[👁️ Sistema de Monitores](../README.md)** - Documentación de monitores
- **[📁 File Monitor](../file_monitor/README.md)** - Monitor del sistema de archivos
- **[🌐 Network Monitor](../network_monitor/README.md)** - Monitor de red
- **[🎯 Behavior Detector](../../detectors/behavior_detector/README.md)** - Análisis de comportamiento
- **[⌨️ Keylogger Detector](../../detectors/keylogger_detector/README.md)** - Detección especializada
- **[📊 Core Engine](../../../core/README.md)** - Event Bus y motor principal
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Monitoreo Continuo de Procesos**