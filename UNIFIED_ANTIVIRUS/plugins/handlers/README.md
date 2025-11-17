# ⚡ Carpeta `/plugins/handlers` - Manejadores de Eventos

## Descripción General

La carpeta `plugins/handlers/` contiene los plugins que **responden a amenazas detectadas**. Mientras los detectores identifican amenazas, los handlers **toman acción**: alertan al usuario, ponen archivos en cuarentena, y registran eventos para auditoría.

Los handlers implementan `HandlerInterface` y se suscriben a eventos del Event Bus como `threat_detected`, ejecutando acciones automáticas o solicitando confirmación del usuario.

## 🎯 Tipos de Handlers

1. **Alert Manager**: Notificaciones y alertas al usuario
2. **Quarantine Handler**: Aislamiento de archivos maliciosos
3. **Logger Handler**: Registro estructurado de eventos

## 📁 Estructura de Handlers

```
plugins/handlers/
├── alert_manager/      # Gestión de alertas
│   ├── __init__.py
│   ├── plugin.py
│   └── config.json
│
├── quarantine_handler/ # Sistema de cuarentena
│   ├── __init__.py
│   ├── plugin.py
│   └── config.json
│
└── logger_handler/     # Logging estructurado
    ├── __init__.py
    ├── plugin.py
    └── config.json
```

---

## 🚨 Alert Manager - Gestión de Alertas

### `plugin.py`
**Propósito**: Gestionar alertas y notificaciones del sistema

**Funcionalidad**:
- Múltiples canales de notificación (consola, archivo, email, desktop)
- Niveles de severidad (INFO, WARNING, CRITICAL, EMERGENCY)
- Rate limiting para evitar spam
- Historial de alertas
- Suscriptores configurables

**Descripción Técnica**:

**Clase Principal**: `AlertManagerPlugin`

**Canales de alerta**:
```python
alert_channels = {
    'console': self._send_console_alert,
    'file': self._send_file_alert,
    'email': self._send_email_alert,
    'system': self._send_system_alert
}
```

**Métodos clave**:

1. **`handle_event(event_type, event_data)`**:
   ```python
   if event_type == "threat_detected":
       return self._handle_threat_alert(event_data)
   elif event_type == "system_error":
       return self._handle_error_alert(event_data)
   ```

2. **`handle_alert(level, message, details)`**:
   ```python
   alert = {
       'id': unique_id,
       'timestamp': datetime.now(),
       'level': level,  # INFO, WARNING, CRITICAL
       'message': message,
       'details': details
   }
   
   # Enviar a canales apropiados según nivel
   for channel, handler in self.alert_channels.items():
       if self._should_send_to_channel(channel, level):
           handler(alert)
   
   # Guardar en historial
   self.alert_history.append(alert)
   ```

3. **`_send_desktop_notification(alert)`**:
   ```python
   # Windows: usa win10toast o plyer
   # Linux: usa notify-send
   # macOS: usa osascript
   notification.notify(
       title=f"Antivirus Alert [{alert['level']}]",
       message=alert['message'],
       timeout=10
   )
   ```

**Configuración** (`config.json`):
```json
{
    "channels": {
        "console": {"enabled": true, "level": "INFO"},
        "file": {"enabled": true, "path": "logs/alerts.log"},
        "email": {"enabled": false, "smtp_server": ""},
        "system": {"enabled": true, "show_notifications": true}
    },
    "max_notifications_per_minute": 5,
    "alert_timeout": 300
}
```

**Eventos manejados**:
- `threat_detected`: Amenaza detectada
- `system_error`: Error del sistema
- `plugin_activated/deactivated`: Cambios de estado
- `quarantine_success/failure`: Resultados de cuarentena

---

## 🔒 Quarantine Handler - Sistema de Cuarentena

### `plugin.py`
**Propósito**: Aislar archivos maliciosos de forma segura

**Funcionalidad**:
- Mueve archivos a zona de cuarentena
- Cifrado opcional de archivos
- Restauración de archivos
- Eliminación permanente
- Metadata de archivos en cuarentena

**Descripción Técnica**:

**Clase Principal**: `QuarantineHandlerPlugin`

**Base de datos de cuarentena**:
```json
{
    "files": {
        "quarantine_id_1": {
            "original_path": "C:\\Users\\...",
            "quarantine_path": "quarantine/...",
            "sha256": "hash",
            "quarantined_at": "2025-11-02T10:30:00",
            "reason": "Keylogger detected",
            "risk_level": "CRITICAL",
            "can_restore": true,
            "size_bytes": 1024
        }
    }
}
```

**Métodos clave**:

1. **`quarantine_file(file_path, reason, metadata)`**:
   ```python
   # Verificar archivo existe
   if not Path(file_path).exists():
       return False
   
   # Calcular hash
   sha256 = self._calculate_hash(file_path)
   
   # Generar ID único
   quarantine_id = f"q_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{sha256[:8]}"
   
   # Backup si configurado
   if self.config['backup_original']:
       self._create_backup(file_path)
   
   # Mover a cuarentena
   quarantine_path = self.quarantine_dir / quarantine_id
   shutil.move(file_path, quarantine_path)
   
   # Cifrar si habilitado
   if self.config['encrypt_files']:
       self._encrypt_file(quarantine_path)
   
   # Registrar en DB
   self._add_to_quarantine_db(quarantine_id, metadata)
   
   # Publicar evento
   event_bus.publish('file_quarantined', {
       'quarantine_id': quarantine_id,
       'original_path': file_path
   })
   ```

2. **`restore_file(quarantine_id)`**:
   ```python
   # Verificar existe en cuarentena
   entry = self.quarantine_db['files'].get(quarantine_id)
   if not entry:
       return False
   
   # Verificar puede restaurarse
   if not entry['can_restore']:
       return False
   
   # Descifrar si necesario
   if entry.get('encrypted'):
       self._decrypt_file(entry['quarantine_path'])
   
   # Restaurar a ubicación original
   shutil.move(entry['quarantine_path'], entry['original_path'])
   
   # Remover de DB
   del self.quarantine_db['files'][quarantine_id]
   self._save_quarantine_db()
   ```

3. **`delete_permanently(quarantine_id)`**:
   ```python
   # Eliminación segura (sobrescribir antes de borrar)
   quarantine_path = self._get_quarantine_path(quarantine_id)
   
   # Sobrescribir con datos aleatorios
   self._secure_delete(quarantine_path)
   
   # Remover de DB
   del self.quarantine_db['files'][quarantine_id]
   ```

**Configuración** (`config.json`):
```json
{
    "quarantine_directory": "quarantine",
    "max_file_size": "100MB",
    "retention_days": 30,
    "compress_files": true,
    "encrypt_files": false,
    "auto_cleanup": true,
    "backup_before_quarantine": true
}
```

**Operaciones soportadas**:
- `quarantine`: Mover archivo a cuarentena
- `restore`: Restaurar archivo
- `delete`: Eliminar permanentemente
- `list`: Listar archivos en cuarentena
- `info`: Información detallada de archivo

---

## 📝 Logger Handler - Logging Estructurado

### `plugin.py`
**Propósito**: Registro estructurado de todos los eventos del sistema

**Funcionalidad**:
- Logging en formato JSON (JSONL)
- Múltiples niveles de logging
- Rotación automática de logs
- Indexación para búsquedas rápidas
- Exportación de logs

**Descripción Técnica**:

**Clase Principal**: `LoggerHandlerPlugin`

**Formato de log estructurado**:
```json
{
    "timestamp": "2025-11-02T10:30:00.123456",
    "event_id": "evt_20251102_103000_abc123",
    "event_type": "threat_detected",
    "severity": "CRITICAL",
    "source": "ml_detector",
    "data": {
        "process_name": "suspicious.exe",
        "threat_type": "keylogger",
        "confidence": 0.95
    },
    "context": {
        "system_uptime": 3600,
        "active_plugins": 8
    }
}
```

**Métodos clave**:

1. **`handle_event(event_type, event_data)`**:
   ```python
   # Construir entrada de log estructurado
   log_entry = {
       'timestamp': datetime.now().isoformat(),
       'event_id': self._generate_event_id(),
       'event_type': event_type,
       'severity': self._determine_severity(event_type),
       'source': event_data.get('source', 'unknown'),
       'data': event_data,
       'context': self._gather_context()
   }
   
   # Escribir en archivo JSONL
   self._write_log_entry(log_entry)
   
   # Indexar para búsquedas
   if self.enable_indexing:
       self._index_log_entry(log_entry)
   ```

2. **`_write_log_entry(entry)`**:
   ```python
   # Escribir línea JSON en archivo
   with open(self.log_file, 'a', encoding='utf-8') as f:
       json.dump(entry, f)
       f.write('\n')
   
   # Verificar rotación
   if self._should_rotate_log():
       self._rotate_log_file()
   ```

3. **`query_logs(filters, start_time, end_time)`**:
   ```python
   # Búsqueda eficiente en logs
   results = []
   
   with open(self.log_file, 'r') as f:
       for line in f:
           entry = json.loads(line)
           
           # Aplicar filtros
           if self._matches_filters(entry, filters):
               if start_time <= entry['timestamp'] <= end_time:
                   results.append(entry)
   
   return results
   ```

**Configuración** (`config.json`):
```json
{
    "log_directory": "logs",
    "log_file": "events.jsonl",
    "max_log_size": "50MB",
    "max_log_files": 10,
    "enable_indexing": true,
    "index_fields": ["event_type", "severity", "source"],
    "retention_days": 90
}
```

**Tipos de eventos registrados**:
- Todos los eventos del sistema
- Detecciones de amenazas
- Cambios de configuración
- Errores y excepciones
- Inicio/detención de plugins
- Acciones de usuario

---

## 🔄 Flujo de Handlers

```
┌─────────────────────────────────────┐
│         Detector Plugins            │
│  (Detect threat, analyze risk)      │
└────────────────┬────────────────────┘
                 │
                 ▼ publish threat_detected
          ┌─────────────┐
          │  Event Bus  │
          └──────┬──────┘
                 │
        ┌────────┼────────┐
        │        │         │
        ▼        ▼         ▼
┌───────────┐ ┌──────────┐ ┌──────────┐
│   Alert   │ │Quarantine│ │  Logger  │
│  Manager  │ │ Handler  │ │ Handler  │
└─────┬─────┘ └────┬─────┘ └────┬─────┘
      │            │            │
      ▼            ▼            ▼
┌──────────┐ ┌───────────┐ ┌──────────┐
│ Notify   │ │ Isolate   │ │  Record  │
│  User    │ │   File    │ │  Event   │
└──────────┘ └───────────┘ └──────────┘
```

## 📊 Coordinación entre Handlers

Los handlers pueden coordinarse para respuestas complejas:

```python
# Threat detected con severidad CRITICAL
event_data = {
    'threat_type': 'keylogger',
    'file_path': 'suspicious.exe',
    'risk_level': 'CRITICAL'
}

# Alert Manager: Notifica al usuario
alert_manager.handle_alert('CRITICAL', 'Keylogger detected', event_data)

# Quarantine Handler: Aísla archivo
quarantine_handler.quarantine_file(
    event_data['file_path'],
    reason='Keylogger detected',
    metadata=event_data
)

# Logger Handler: Registra todo
logger_handler.log_event('threat_response', {
    'threat': event_data,
    'actions_taken': ['alert_sent', 'file_quarantined']
})
```

## ⚙️ Configuración de Handlers

Los handlers son altamente configurables:
- **Alert Manager**: Canales, umbrales, rate limiting
- **Quarantine**: Políticas de retención, cifrado, auto-quarantine
- **Logger**: Formato, rotación, indexación

## 💡 Mejores Prácticas

1. **Confirmación del usuario**: No acciones destructivas sin confirmación
2. **Logging completo**: Registrar todas las acciones para auditoría
3. **Reversibilidad**: Permitir deshacer acciones (restore desde cuarentena)
4. **Rate limiting**: Evitar spam de alertas
5. **Priorización**: Manejar amenazas críticas primero

## 🧪 Testing de Handlers

```python
# Test Alert Manager
alert_manager.handle_alert('WARNING', 'Test alert', {'test': True})
assert len(alert_manager.alert_history) > 0

# Test Quarantine
quarantine_id = quarantine_handler.quarantine_file('test.exe', 'Test')
assert quarantine_handler.is_quarantined(quarantine_id)
quarantine_handler.restore_file(quarantine_id)
```

## 🔗 **Enlaces a Handlers Específicos**

### Handlers Principales
- **[🚨 Alert Manager](alert_manager/README.md)** - Gestión de alertas y notificaciones
- **[🔒 Quarantine Handler](quarantine_handler/README.md)** - Sistema de cuarentena de archivos
- **[📝 Logger Handler](logger_handler/README.md)** - Logging estructurado de eventos

### Enlaces Relacionados
- **[📋 README Principal](../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../README.md)** - Arquitectura de plugins
- **[🔍 Detectores](../detectors/README.md)** - Sistema de detección
- **[👁️ Monitores](../monitors/README.md)** - Sistema de monitoreo
- **[🧠 Recursos Compartidos](../shared/README.md)** - Motor de inteligencia unificado
- **[📊 Core Engine](../../core/README.md)** - Event Bus y motor principal
- **[⚙️ Configuración](../../config/README.md)** - Sistema de configuración
- **[📝 Logs](../../logs/README.md)** - Sistema de logging central

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../README.md) - Sistema de Respuesta Automatizada**

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
