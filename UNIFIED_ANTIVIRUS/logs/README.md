# 📝 Sistema de Logs Centralizado

## Descripción General

Directorio centralizado que contiene todos los archivos de log del sistema UNIFIED_ANTIVIRUS. Proporciona un repositorio unificado para auditoría, debugging, monitoreo y análisis forense de la actividad del antivirus.

## 🎯 Tipos de Logs

### 📊 **Logs del Sistema Principal**
- **`antivirus.log`** - Log principal del sistema completo
- **`performance.log`** - Métricas de rendimiento y recursos
- **`audit.log`** - Eventos de auditoría y seguridad
- **`threats.log`** - Registro de amenazas detectadas
- **`launcher.log`** - Eventos de inicio y configuración

### 🔍 **Logs de Detectores**
- **`behavior_detector.log`** - Análisis de comportamiento heurístico
- **`keylogger_detector.log`** - Detección especializada de keyloggers
- **`ml_detector.log`** - Predicciones y análisis de ML
- **`network_detector.log`** - Análisis de tráfico de red
- **`advanced_keylogger_detector.log`** - Detector avanzado generado
- **`usb_malware_detector.log`** - Detección de malware USB

### 🛡️ **Logs de Seguridad y Testing**
- **`iast_detector.log`** - Auto-protección y análisis IAST
- **`IASTDetectorPlugin.log`** - Plugin IAST especializado
- **`test_system.log`** - Logs de testing del sistema
- **`iast_integration_test.log`** - Tests de integración IAST

### 🌐 **Logs de Interface**
- **`frontend.log`** - Interface web del sistema
- **`tkinter_ui.log`** - Interface gráfica de usuario

## 📁 Estructura de Archivos

```
logs/
├── Sistema Principal
│   ├── antivirus.log                    # Log principal
│   ├── performance.log                  # Métricas de rendimiento
│   ├── audit.log                       # Auditoría y compliance
│   ├── threats.log                     # Amenazas detectadas
│   └── launcher.log                    # Inicio del sistema
│
├── Detectores
│   ├── behavior_detector.log           # Detección heurística
│   ├── keylogger_detector.log          # Keyloggers especializados
│   ├── ml_detector.log                 # Machine Learning
│   ├── network_detector.log            # Análisis de red
│   ├── advanced_keylogger_detector.log # Detector avanzado
│   └── usb_malware_detector.log        # Malware USB
│
├── Seguridad IAST
│   ├── iast_detector.log               # IAST principal
│   ├── IASTDetectorPlugin.log          # Plugin IAST
│   ├── IASTDetectorPlugin_errors.log   # Errores IAST
│   └── IASTDetectorPlugin_structured.jsonl # Logs estructurados
│
├── Testing
│   ├── test_system.log                 # Tests del sistema
│   ├── test_system_errors.log          # Errores de testing
│   ├── test_system_structured.jsonl    # Tests estructurados
│   ├── iast_integration_test.log       # Tests IAST
│   └── iast_integration_test_errors.log
│
└── Interfaces
    ├── frontend.log                    # Web interface
    └── tkinter_ui.log                  # GUI desktop
```

## 🔍 **Formatos de Log**

### Log Tradicional
```
2024-11-08 15:30:45,123 - INFO - keylogger_detector - Suspicious process detected: suspicious.exe
2024-11-08 15:30:45,456 - WARNING - behavior_detector - High CPU usage detected: 85%
2024-11-08 15:30:45,789 - CRITICAL - quarantine_handler - File quarantined: malware.exe
```

### Log Estructurado (JSON Lines)
```json
{"timestamp":"2024-11-08T15:30:45.123Z","level":"INFO","component":"keylogger_detector","message":"Suspicious process detected","metadata":{"process":"suspicious.exe","pid":1234,"confidence":0.85}}
{"timestamp":"2024-11-08T15:30:45.456Z","level":"WARNING","component":"behavior_detector","message":"High CPU usage detected","metadata":{"cpu_percent":85,"threshold":80}}
{"timestamp":"2024-11-08T15:30:45.789Z","level":"CRITICAL","component":"quarantine_handler","message":"File quarantined","metadata":{"file":"malware.exe","quarantine_id":"QTN_001"}}
```

### Log de Errores
```
2024-11-08 15:30:45,999 - ERROR - ml_detector - Model loading failed
Traceback (most recent call last):
  File "ml_detector.py", line 45, in load_model
    model = load_onnx_model(path)
FileNotFoundError: Model file not found: modelo.onnx
```

## 📊 **Análisis de Logs**

### Métricas Principales
- **Amenazas detectadas por día/hora**
- **Performance del sistema (CPU, RAM)**
- **Errores y excepciones por componente**
- **Tiempo de respuesta de detectores**
- **Actividad de cuarentena**

### Consultas Típicas
```bash
# Amenazas detectadas hoy
grep "$(date +%Y-%m-%d)" threats.log | grep "CRITICAL"

# Errores del ML detector
grep "ERROR" ml_detector.log | tail -20

# Performance del sistema
grep "performance" performance.log | grep "$(date +%Y-%m-%d)"

# Actividad de cuarentena
grep "quarantined" antivirus.log | wc -l
```

## 🔧 **Gestión de Logs**

### Rotación Automática
Los logs se rotan automáticamente cuando:
- **Tamaño**: Archivos >10MB se rotan
- **Tiempo**: Rotación diaria a medianoche
- **Backup**: Se mantienen 7 copias históricas
- **Compresión**: Logs antiguos se comprimen (.gz)

### Limpieza Automática
```python
# Política de retención
retention_policy = {
    'antivirus.log': 30,      # 30 días
    'threats.log': 90,        # 90 días (auditoría)
    'performance.log': 14,    # 14 días
    'test_*.log': 7,         # 7 días
    '*_errors.log': 60       # 60 días (debugging)
}
```

### Niveles de Log
- **🔵 DEBUG**: Información detallada para desarrollo
- **🟢 INFO**: Eventos normales del sistema
- **🟡 WARNING**: Situaciones que requieren atención
- **🔴 ERROR**: Errores que no detienen el sistema
- **🚨 CRITICAL**: Errores críticos que requieren intervención

## 🛡️ **Logs de Seguridad**

### Audit Trail
```json
{
  "timestamp": "2024-11-08T15:30:45Z",
  "event_type": "threat_detected",
  "severity": "critical",
  "user": "system",
  "source_ip": "local",
  "target": "C:\\malware.exe",
  "action_taken": "quarantine",
  "detector": "keylogger_detector",
  "confidence": 0.95,
  "hash": "sha256:abc123...",
  "session_id": "sess_001"
}
```

### Compliance Logs
- **ISO 27001**: Logs de eventos de seguridad
- **SOC**: Registros para centro de operaciones
- **Forensics**: Trail completo para análisis forense
- **GDPR**: Logs de acceso y procesamiento de datos

## 🚀 **Herramientas de Análisis**

### Log Aggregation
```bash
# Resumen de amenazas por detector
awk '/threat_detected/ {print $5}' threats.log | sort | uniq -c

# Top procesos sospechosos
grep "suspicious process" */detector.log | awk '{print $NF}' | sort | uniq -c | sort -nr

# Performance timeline
grep "performance" performance.log | awk '{print $1, $2, $8}' | tail -100
```

### Alertas Automáticas
```python
# Configuración de alertas
alert_rules = {
    'error_threshold': 10,        # >10 errores/hora
    'critical_threats': 1,        # >1 amenaza crítica
    'performance_degradation': 5, # >5 eventos de performance
    'quarantine_failures': 3     # >3 fallos de cuarentena
}
```

## 📈 **Monitoreo en Tiempo Real**

### Tail de Logs Críticos
```bash
# Monitoreo en tiempo real
tail -f antivirus.log threats.log | grep -E "(CRITICAL|ERROR)"

# Dashboard de amenazas
watch -n 5 'grep "$(date +%Y-%m-%d)" threats.log | wc -l'

# Performance en vivo  
tail -f performance.log | grep -E "(CPU|Memory)"
```

### Métricas en Vivo
- **Amenazas/minuto**: Tasa de detección actual
- **CPU/Memory**: Uso de recursos en tiempo real
- **Errores/minuto**: Tasa de errores del sistema
- **Latencia**: Tiempo de respuesta de componentes

## 🔧 **Troubleshooting con Logs**

### Análisis de Problemas Comunes

#### **Sistema Lento**
```bash
# Verificar performance logs
grep "high_cpu\|high_memory" performance.log | tail -20

# Detectores con problemas
grep "timeout\|slow" */detector.log | head -10
```

#### **Falsos Positivos**
```bash
# Revisar confianza de detecciones
grep "confidence.*0\.[0-5]" threats.log | tail -20

# Patrones problemáticos
grep "false_positive" behavior_detector.log
```

#### **Errores de Cuarentena**
```bash
# Fallos de cuarentena
grep "quarantine.*failed" antivirus.log

# Permisos insuficientes
grep "permission.*denied" */log
```

## 🔗 **Enlaces Relacionados**

### Componentes que Generan Logs
- **[📋 README Principal](../README.md)** - Navegación general del proyecto
- **[📊 Core Engine](../core/README.md)** - Motor principal que coordina logging
- **[📝 Logger Handler](../plugins/handlers/logger_handler/README.md)** - Handler de logging estructurado
- **[🛠️ Utils Logger](../utils/README.md)** - Sistema de logging base
- **[🔍 Detectores](../plugins/detectors/README.md)** - Generadores de logs de detección
- **[👁️ Monitores](../plugins/monitors/README.md)** - Logs de monitoreo continuo
- **[🚨 Handlers](../plugins/handlers/README.md)** - Logs de respuesta del sistema

### Configuración y Análisis
- **[⚙️ Configuración](../config/README.md)** - Configuración de logging del sistema
- **[🛡️ Threat Intelligence](../threat_intel/README.md)** - Fuente de datos para logs de amenazas
- **[🔌 Sistema de Plugins](../plugins/README.md)** - Arquitectura que genera logs

### Herramientas de Análisis
- **`real_time_logs.py`** en utils/ - Análisis en tiempo real
- **`metrics_collector.py`** en utils/ - Recolección de métricas
- **`audit.log`** - Trail de auditoría completo
- **`performance.log`** - Monitoreo de rendimiento

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../README.md) - Sistema de Logging Centralizado y Auditoría**

**Retención**: 30-90 días según tipo  
**Formato**: Texto plano + JSON estructurado  
**Rotación**: Automática por tamaño y tiempo