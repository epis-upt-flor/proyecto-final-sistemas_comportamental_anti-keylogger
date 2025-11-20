# 📝 Logger Handler Plugin

## Descripción General

Plugin especializado en el registro estructurado y centralizado de todos los eventos del sistema antivirus. Proporciona logging avanzado, correlación de eventos y análisis forense para auditoría y troubleshooting.

## 🎯 Funcionalidades Principales

### ✅ **Logging Estructurado**
- **Formato JSON**: Logs estructurados para análisis automatizado
- **Múltiples niveles**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Correlación de eventos**: IDs únicos para seguimiento de eventos relacionados
- **Metadata enriquecida**: Contexto completo de cada evento

### 📊 **Gestión de Logs**
- **Rotación automática**: Archivos de log rotan por tamaño/tiempo
- **Compresión**: Logs antiguos comprimidos automáticamente
- **Retención**: Políticas configurables de retención de logs
- **Indexación**: Índices para búsqueda rápida de eventos

### 🔍 **Análisis y Auditoría**
- **Timeline de eventos**: Reconstrucción cronológica de actividad
- **Agregación**: Estadísticas y métricas de eventos del sistema
- **Alertas**: Detección de patrones anómalos en logs
- **Export**: Exportación para herramientas de análisis externas

## 📁 Archivos del Plugin

```
logger_handler/
├── plugin.py          # LoggerHandlerPlugin principal
├── config.json        # Configuración de logging
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "logging_config": {
    "log_level": "INFO",
    "log_format": "json",
    "enable_console_logging": true,
    "enable_file_logging": true,
    "enable_structured_logging": true
  },
  "file_logging": {
    "log_directory": "logs",
    "main_log_file": "antivirus.log",
    "event_log_file": "events.jsonl",
    "error_log_file": "errors.log",
    "max_file_size_mb": 100,
    "backup_count": 10,
    "compress_backups": true
  },
  "structured_logging": {
    "include_timestamps": true,
    "include_thread_info": true,
    "include_process_info": true,
    "include_correlation_ids": true,
    "enrich_with_metadata": true
  },
  "retention": {
    "keep_logs_days": 90,
    "cleanup_interval_hours": 24,
    "compress_after_days": 7,
    "archive_after_days": 30
  },
  "alerting": {
    "alert_on_errors": true,
    "error_threshold_per_hour": 10,
    "alert_on_patterns": [
      "repeated_quarantine_failures",
      "multiple_threats_detected",
      "system_performance_degradation"
    ]
  }
}
```

### Estructura de Logs
```
logs/
├── antivirus.log          # Log principal del sistema
├── events.jsonl           # Eventos estructurados (JSON Lines)
├── errors.log            # Errores y excepciones
├── performance.log       # Métricas de performance
├── security.log          # Eventos de seguridad
├── archived/             # Logs archivados
│   ├── 2024-10/
│   └── 2024-11/
└── compressed/           # Logs comprimidos
    ├── antivirus.log.1.gz
    └── events.jsonl.1.gz
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `*` - El logger se suscribe a TODOS los eventos del sistema
- `threat_detected` - Amenazas detectadas
- `file_quarantined` - Operaciones de cuarentena
- `alert_sent` - Alertas enviadas
- `plugin_error` - Errores de plugins
- `system_event` - Eventos del sistema
- `performance_metric` - Métricas de rendimiento

### **Eventos Publicados:**
- `log_written` - Log escrito exitosamente
- `log_error` - Error en escritura de log
- `log_rotated` - Rotación de log ejecutada
- `log_cleaned` - Limpieza automática completada

### **Estructura de Log JSON:**
```json
{
  "timestamp": "2024-11-08T15:30:45.123Z",
  "level": "WARNING",
  "logger": "keylogger_detector",
  "message": "Suspicious process detected",
  "correlation_id": "corr_20241108_001",
  "event_type": "threat_detected",
  "thread_id": 12345,
  "process_id": 6789,
  "metadata": {
    "detector": "keylogger_detector",
    "confidence": 0.85,
    "process_name": "suspicious.exe",
    "process_pid": 1234,
    "detection_method": "behavior_analysis"
  },
  "context": {
    "session_id": "sess_20241108_startup",
    "user": "user123",
    "hostname": "DESKTOP-ABC123",
    "antivirus_version": "2.0.0"
  },
  "performance": {
    "processing_time_ms": 45.2,
    "memory_usage_mb": 128.5,
    "cpu_usage_percent": 12.3
  }
}
```

## 🚀 **Uso del Plugin**

### Inicialización Automática
```python
# El plugin se registra automáticamente y captura todos los eventos
engine.activate_category('handlers')
```

### Logging Programático
```python
# Usar el logger handler directamente
logger_handler = LoggerHandlerPlugin()

# Log simple
logger_handler.log(
    level="INFO",
    message="Scan completed successfully",
    metadata={"files_scanned": 1000, "threats_found": 0}
)

# Log con correlación
logger_handler.log_correlated(
    level="WARNING", 
    message="Multiple threats in same directory",
    correlation_id="corr_batch_001",
    events=related_events
)

# Log de performance
logger_handler.log_performance(
    operation="full_scan",
    duration_seconds=45.2,
    resources_used={"cpu": "15%", "memory": "200MB"}
)
```

## 📈 **Métricas y Estadísticas**

### Métricas del Logger
```python
logger_stats = {
    'total_logs_written': 0,         # Total de logs escritos
    'logs_by_level': {               # Distribución por nivel
        'DEBUG': 0,
        'INFO': 0,
        'WARNING': 0,
        'ERROR': 0,
        'CRITICAL': 0
    },
    'logs_by_source': {},            # Logs por plugin/componente
    'log_files_created': 0,          # Archivos de log creados
    'log_rotations': 0,              # Rotaciones ejecutadas
    'compressed_logs': 0,            # Logs comprimidos
    'storage_used_mb': 0.0,          # Espacio usado por logs
    'average_log_size_bytes': 0,     # Tamaño promedio de log
    'uptime_hours': 0.0             # Tiempo de funcionamiento
}
```

### Performance del Logger
- **Latencia de escritura**: < 1ms para logs simples
- **Throughput**: >10,000 logs/segundo en modo async
- **Uso de memoria**: < 50MB para buffer de logs
- **Overhead de sistema**: < 0.5% CPU en operación normal

## 🔍 **Análisis de Logs**

### Correlación de Eventos
```python
# El logger automáticamente correlaciona eventos relacionados
correlation_example = {
    "correlation_id": "corr_threat_001",
    "events": [
        {"event": "process_created", "timestamp": "15:30:45.123"},
        {"event": "suspicious_behavior", "timestamp": "15:30:47.456"}, 
        {"event": "threat_detected", "timestamp": "15:30:50.789"},
        {"event": "file_quarantined", "timestamp": "15:30:52.012"}
    ],
    "timeline_duration_ms": 6889,
    "total_events": 4
}
```

### Patrones de Análisis
```python
log_patterns = {
    'threat_detection_chain': {
        'pattern': ['process_created', 'suspicious_behavior', 'threat_detected'],
        'max_time_window_seconds': 30,
        'alert_threshold': 5  # 5 cadenas en 1 hora = alerta
    },
    'system_degradation': {
        'pattern': ['high_cpu_usage', 'high_memory_usage', 'slow_response'],
        'consecutive_occurrences': 3,
        'alert_level': 'WARNING'
    },
    'quarantine_failure_burst': {
        'pattern': ['quarantine_failed'],
        'count_threshold': 10,
        'time_window_minutes': 5
    }
}
```

## 📊 **Herramientas de Análisis**

### Query de Logs
```python
# Búsqueda de logs por criterios
logs = logger_handler.query_logs(
    level="ERROR",
    start_time="2024-11-08T10:00:00",
    end_time="2024-11-08T16:00:00",
    source="keylogger_detector",
    limit=100
)

# Agregación de eventos
threat_summary = logger_handler.aggregate_events(
    event_type="threat_detected",
    group_by="detector",
    time_range="last_24_hours"
)

# Timeline de eventos correlacionados
timeline = logger_handler.get_event_timeline(
    correlation_id="corr_20241108_001"
)
```

### Export y Integración
```python
# Export para análisis externo
logger_handler.export_logs(
    format="csv",
    output_file="analysis_data.csv",
    date_range="last_week",
    include_metadata=True
)

# Integration con SIEM
siem_data = logger_handler.format_for_siem(
    format="cef",  # Common Event Format
    events=recent_security_events
)
```

## 🛡️ **Características de Seguridad**

### Integridad de Logs
```python
# Los logs incluyen checksums para verificar integridad
log_integrity = {
    'checksum_algorithm': 'SHA256',
    'tamper_detection': True,
    'digital_signatures': False,  # Opcional para compliance
    'append_only': True           # Previene modificación de logs
}
```

### Logs de Seguridad
```python
# Eventos de seguridad se registran con mayor detalle
security_log_entry = {
    "event_type": "security_event",
    "severity": "HIGH",
    "category": "threat_detected", 
    "source_ip": "192.168.1.100",
    "user_context": "user123",
    "asset_affected": "workstation_001",
    "ioc_indicators": ["suspicious.exe", "malicious_ip"],
    "response_actions": ["quarantine", "alert_sent"]
}
```

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Test unitario completo
python -m pytest plugins/handlers/logger_handler/

# Test de performance de logging
cd plugins/handlers/logger_handler
python plugin.py --benchmark-logging

# Test de rotación de logs
python plugin.py --test-rotation

# Verificar integridad de logs
python plugin.py --verify-integrity

# Simulación de carga de logs
python plugin.py --stress-test --duration=60
```

### Debugging y Administración
```python
# Verificar estado del logger
status = logger_handler.get_status()
print(f"Logs written: {status['total_logs']}")
print(f"Storage used: {status['storage_mb']} MB")

# Forzar rotación de logs
logger_handler.force_rotation()

# Limpiar logs antiguos
cleaned_files = logger_handler.cleanup_old_logs(days_older_than=30)

# Reconstruir índices
logger_handler.rebuild_indexes()
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **Logs No Se Escriben**
```
Causa: Permisos insuficientes o disco lleno
Solución:
- Verificar permisos de escritura en directorio de logs
- Comprobar espacio disponible en disco
- Verificar que servicio de logging esté activo
```

#### **Performance Degradada**
```
Causa: Logging síncrono o logs muy grandes
Solución:
- Habilitar async logging en configuración
- Reducir nivel de log de DEBUG a INFO
- Aumentar intervalo de rotación de logs
- Optimizar queries de búsqueda en logs
```

#### **Logs Corruptos**
```
Causa: Interrupción de escritura o problemas de disco
Solución:
- Verificar integridad con: python plugin.py --verify-integrity
- Reconstruir índices corruptos
- Restaurar desde backups si es necesario
- Verificar salud del sistema de archivos
```

### Optimización
- **Async writing**: Escribir logs en threads separados
- **Batching**: Agrupar múltiples logs en una escritura
- **Compression**: Comprimir logs automáticamente
- **Indexing**: Crear índices para búsquedas frecuentes

## 📚 **Integración Forense**

### Análisis Post-Incidente
```python
# Reconstrucción de timeline de incidente
incident_timeline = logger_handler.reconstruct_incident(
    start_time="2024-11-08T15:00:00",
    end_time="2024-11-08T16:00:00",
    correlation_ids=["corr_incident_001"],
    include_context=True
)

# Extracción de evidencia
evidence = logger_handler.extract_evidence(
    case_id="CASE_001",
    event_types=["threat_detected", "file_quarantined"],
    preserve_chain_of_custody=True
)
```

### Compliance y Auditoría
- **Retención de logs**: Políticas configurables de retención
- **Immutable logs**: Logs de solo escritura para compliance
- **Audit trails**: Seguimiento completo de acciones del sistema
- **Reporting**: Generación de reportes de auditoría automáticos

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🚨 Sistema de Handlers](../README.md)** - Documentación de handlers
- **[🚨 Alert Manager](../alert_manager/README.md)** - Sistema de alertas
- **[🔒 Quarantine Handler](../quarantine_handler/README.md)** - Sistema de cuarentena
- **[📊 Core Engine](../../../core/README.md)** - Event Bus para captura de eventos
- **[⚙️ Configuración](../../../config/README.md)** - Configuración de logging
- **[📝 Logs](../../../logs/README.md)** - Directorio central de logs
- **[🔍 Detectores](../../detectors/README.md)** - Fuentes de eventos de detección

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Logging y Auditoría Forense**