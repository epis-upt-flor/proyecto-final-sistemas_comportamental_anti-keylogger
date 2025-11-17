# 🚨 Alert Manager Plugin

## Descripción General

Plugin especializado en la gestión y distribución de alertas del sistema antivirus. Proporciona múltiples canales de notificación y niveles de severidad para informar al usuario sobre amenazas detectadas y eventos del sistema en tiempo real.

## 🎯 Funcionalidades Principales

### ✅ **Canales de Alertas**
- **Consola**: Alertas en tiempo real en la terminal
- **Sistema**: Notificaciones nativas del sistema operativo
- **Archivo**: Registro de alertas en archivos de log
- **Email**: Envío de alertas por correo electrónico (opcional)
- **Desktop**: Notificaciones popup en el escritorio

### 📊 **Niveles de Severidad**
- **🔵 INFO**: Información general del sistema
- **🟡 WARNING**: Advertencias que requieren atención
- **🔴 CRITICAL**: Amenazas críticas detectadas
- **🚨 EMERGENCY**: Situaciones que requieren acción inmediata

### 🔧 **Gestión Inteligente**
- **Rate Limiting**: Prevención de spam de alertas
- **Deduplicación**: Evita alertas duplicadas en períodos cortos
- **Historial**: Mantiene registro de todas las alertas enviadas
- **Filtrado**: Filtros configurables por tipo y severidad

## 📁 Archivos del Plugin

```
alert_manager/
├── plugin.py          # AlertManagerPlugin principal
├── config.json        # Configuración de canales y niveles
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "alert_config": {
    "enabled_channels": ["console", "system", "file"],
    "default_level": "WARNING",
    "rate_limit_seconds": 30,
    "deduplicate_window_minutes": 5,
    "max_alerts_per_hour": 50
  },
  "channels": {
    "console": {
      "enabled": true,
      "colored_output": true,
      "timestamp": true,
      "detailed": true
    },
    "system": {
      "enabled": true,
      "show_icon": true,
      "sound": false,
      "persist": true
    },
    "file": {
      "enabled": true,
      "log_file": "logs/alerts.log",
      "rotate": true,
      "max_size_mb": 100
    },
    "email": {
      "enabled": false,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "recipient": "admin@company.com",
      "sender": "antivirus@company.com"
    }
  },
  "severity_config": {
    "INFO": {
      "channels": ["console", "file"],
      "color": "blue",
      "icon": "ℹ️"
    },
    "WARNING": {
      "channels": ["console", "system", "file"],
      "color": "yellow", 
      "icon": "⚠️"
    },
    "CRITICAL": {
      "channels": ["console", "system", "file", "email"],
      "color": "red",
      "icon": "🚨"
    },
    "EMERGENCY": {
      "channels": ["console", "system", "file", "email"],
      "color": "red",
      "icon": "🆘",
      "sound": true,
      "persistent": true
    }
  }
}
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `threat_detected` - Amenaza detectada por detectores
- `system_error` - Error crítico del sistema
- `quarantine_action` - Archivo puesto en cuarentena
- `scan_completed` - Escaneo completo finalizado
- `config_updated` - Configuración actualizada
- `plugin_error` - Error en plugin específico

### **Eventos Publicados:**
- `alert_sent` - Alerta enviada exitosamente
- `alert_failed` - Error al enviar alerta
- `alert_rate_limited` - Alerta bloqueada por rate limiting
- `alert_channel_unavailable` - Canal de alerta no disponible

## 🚀 **Uso del Plugin**

### Inicialización Automática
```python
# El plugin se registra automáticamente
# Se activa con la categoría 'handlers'
engine.activate_category('handlers')
```

### Uso Programático
```python
# Crear alerta manualmente
alert_manager = AlertManagerPlugin()
alert_manager.send_alert(
    level="CRITICAL",
    message="Keylogger detectado",
    details={
        "process": "suspicious.exe",
        "pid": 1234,
        "detection_method": "behavior_analysis"
    }
)

# Alerta con canal específico
alert_manager.send_alert_to_channel(
    channel="email",
    level="EMERGENCY", 
    message="Sistema comprometido",
    details=threat_info
)
```

## 📈 **Métricas y Estadísticas**

### Métricas del Alert Manager
```python
alert_stats = {
    'total_alerts_sent': 0,        # Total de alertas enviadas
    'alerts_by_level': {           # Distribución por severidad
        'INFO': 0,
        'WARNING': 0,
        'CRITICAL': 0,
        'EMERGENCY': 0
    },
    'alerts_by_channel': {         # Distribución por canal
        'console': 0,
        'system': 0,
        'file': 0,
        'email': 0
    },
    'rate_limited_alerts': 0,      # Alertas bloqueadas
    'failed_alerts': 0,            # Alertas fallidas
    'duplicate_alerts_filtered': 0, # Alertas duplicadas filtradas
    'uptime_hours': 0.0            # Tiempo de funcionamiento
}
```

### Performance del Sistema
- **Latencia de alerta**: < 100ms para consola/archivo
- **Latencia sistema**: < 500ms para notificaciones nativas
- **Latencia email**: 1-5 segundos dependiendo de SMTP
- **Throughput**: >1000 alertas/minuto sin rate limiting

## 🔔 **Tipos de Alertas Especializadas**

### Alertas de Amenazas
```python
threat_alert_template = {
    "message": "🚨 AMENAZA DETECTADA: {threat_type}",
    "details": {
        "threat_type": "Keylogger",
        "confidence": 0.95,
        "detection_method": "ML + Behavior Analysis",
        "affected_file": "C:\\Temp\\suspicious.exe",
        "recommended_action": "Cuarentena inmediata"
    }
}
```

### Alertas del Sistema
```python
system_alert_template = {
    "message": "⚙️ EVENTO DEL SISTEMA: {event_type}",
    "details": {
        "event_type": "Plugin Error", 
        "plugin_name": "ml_detector",
        "error_message": "Model file not found",
        "timestamp": "2024-11-08T15:30:45"
    }
}
```

### Alertas de Cuarentena
```python
quarantine_alert_template = {
    "message": "🔒 ARCHIVO EN CUARENTENA: {filename}",
    "details": {
        "filename": "malware.exe",
        "original_path": "C:\\Downloads\\malware.exe",
        "quarantine_id": "QTN_20241108_001",
        "reason": "Keylogger detected by behavior analysis",
        "restore_available": True
    }
}
```

## 🛡️ **Características Avanzadas**

### Rate Limiting Inteligente
```python
# Previene spam de alertas similares
def should_rate_limit(alert):
    recent_alerts = get_recent_alerts(last_30_seconds)
    similar_alerts = filter_similar_alerts(recent_alerts, alert)
    
    if len(similar_alerts) > 3:
        return True  # Rate limit después de 3 alertas similares
    return False
```

### Deduplicación de Alertas
```python
# Evita alertas duplicadas en ventana de tiempo
def is_duplicate_alert(new_alert):
    window = timedelta(minutes=5)
    recent_alerts = get_alerts_in_window(window)
    
    for alert in recent_alerts:
        if alert['message'] == new_alert['message']:
            return True
    return False
```

### Escalamiento de Severidad
```python
# Escala severidad basándose en frecuencia
def escalate_severity(alert_type):
    recent_count = count_recent_alerts(alert_type, hours=1)
    
    if recent_count > 10:
        return "EMERGENCY"  # Muchas alertas del mismo tipo
    elif recent_count > 5:
        return "CRITICAL"
    else:
        return original_level
```

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Test unitario del alert manager
python -m pytest plugins/handlers/alert_manager/

# Test manual de canales
cd plugins/handlers/alert_manager  
python plugin.py --test-channels

# Test de rate limiting
python plugin.py --test-rate-limit

# Simulación de alertas
python plugin.py --simulate-alerts
```

### Debugging y Monitoreo
```python
# Habilitar logging detallado
import logging
logging.basicConfig(level=logging.DEBUG)

# Verificar configuración de canales
alert_manager.check_channel_health()

# Estadísticas en tiempo real
stats = alert_manager.get_statistics()
print(f"Alerts sent: {stats['total_alerts_sent']}")

# Historial de alertas recientes
recent = alert_manager.get_recent_alerts(hours=1)
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **Notificaciones del Sistema No Aparecen**
```
Causa: Permisos o servicio de notificaciones deshabilitado
Solución:
- Verificar permisos de notificaciones en Windows
- Comprobar que el servicio Windows Push Notification esté activo
- Usar canales alternativos (consola, archivo)
```

#### **Emails No Se Envían**
```
Causa: Configuración SMTP incorrecta o credenciales inválidas
Solución:
- Verificar configuración SMTP (servidor, puerto, autenticación)
- Comprobar credenciales de email
- Verificar conectividad de red y firewall
- Usar test: python plugin.py --test-email
```

#### **Demasiadas Alertas (Spam)**
```
Causa: Rate limiting insuficiente o umbrales muy bajos
Solución:
- Aumentar rate_limit_seconds en configuración
- Reducir max_alerts_per_hour
- Aumentar deduplicate_window_minutes
- Revisar umbrales de detección en detectores
```

### Optimización de Performance
- **Async sending**: Enviar alertas en threads separados
- **Batch processing**: Agrupar alertas similares
- **Channel prioritization**: Canales rápidos primero
- **Cleanup scheduling**: Limpiar historial automáticamente

## 📚 **Integración con el Sistema**

### Flujo de Alertas
1. **Detector** encuentra amenaza
2. **Event Bus** distribuye evento `threat_detected`
3. **Alert Manager** recibe evento y evalúa severidad
4. **Rate Limiting** verifica si debe enviar alerta
5. **Deduplicación** evita alertas duplicadas
6. **Canales** distribuyen alerta según configuración
7. **Historial** registra alerta para auditoría

### Respuesta del Usuario
```python
# Alertas interactivas pueden solicitar acción del usuario
interactive_alert = {
    "message": "¿Poner archivo en cuarentena?",
    "actions": ["quarantine", "ignore", "whitelist"],
    "timeout_seconds": 30,
    "default_action": "quarantine"
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🚨 Sistema de Handlers](../README.md)** - Documentación de handlers
- **[🔒 Quarantine Handler](../quarantine_handler/README.md)** - Sistema de cuarentena
- **[📝 Logger Handler](../logger_handler/README.md)** - Sistema de logging
- **[🔍 Detectores](../../detectors/README.md)** - Sistema de detección que genera alertas
- **[📊 Core Engine](../../../core/README.md)** - Event Bus para distribución de eventos
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración
- **[📝 Logs](../../../logs/README.md)** - Logs centralizados del sistema

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Alertas Inteligente**