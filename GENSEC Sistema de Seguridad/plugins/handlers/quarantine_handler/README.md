# 🔒 Quarantine Handler Plugin

## Descripción General

Plugin especializado en el aislamiento seguro de archivos maliciosos detectados por el sistema antivirus. Proporciona cuarentena automática, restauración controlada y gestión completa del ciclo de vida de archivos en cuarentena.

## 🎯 Funcionalidades Principales

### ✅ **Cuarentena Automática**
- **Aislamiento inmediato**: Movimiento seguro de archivos maliciosos
- **Encriptación**: Archivos cifrados en cuarentena para prevenir ejecución
- **Metadatos**: Preservación de información original del archivo
- **Integridad**: Verificación de checksums para detectar alteraciones

### 📊 **Gestión de Cuarentena**
- **Inventario completo**: Lista de todos los archivos en cuarentena
- **Búsqueda avanzada**: Filtrado por fecha, tipo, razón de cuarentena
- **Expiración automática**: Eliminación de archivos antiguos
- **Restauración selectiva**: Recuperación controlada de archivos

### 🔧 **Operaciones Seguras**
- **Backup de archivos**: Copia de seguridad antes de cuarentena
- **Logs detallados**: Registro completo de todas las operaciones
- **Permissions handling**: Gestión correcta de permisos de archivos
- **Path reconstruction**: Recreación de estructura de directorios original

## 📁 Archivos del Plugin

```
quarantine_handler/
├── plugin.py          # QuarantineHandlerPlugin principal
├── config.json        # Configuración de cuarentena
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "quarantine_config": {
    "quarantine_directory": "quarantine",
    "encrypt_files": true,
    "preserve_metadata": true,
    "auto_quarantine": true,
    "max_quarantine_days": 30,
    "max_quarantine_size_gb": 5.0
  },
  "security_settings": {
    "encryption_key": "auto_generated",
    "verify_checksums": true,
    "secure_delete": true,
    "backup_before_quarantine": true
  },
  "auto_actions": {
    "quarantine_on_critical": true,
    "quarantine_on_emergency": true,
    "require_confirmation_on_warning": true,
    "notify_on_quarantine": true
  },
  "cleanup": {
    "auto_cleanup_enabled": true,
    "cleanup_interval_hours": 24,
    "delete_after_days": 30,
    "keep_metadata_after_deletion": true
  }
}
```

### Estructura de Cuarentena
```
quarantine/
├── files/              # Archivos encriptados en cuarentena
│   ├── QTN_20241108_001.enc
│   ├── QTN_20241108_002.enc
│   └── ...
├── metadata/           # Metadatos de archivos
│   ├── QTN_20241108_001.json
│   ├── QTN_20241108_002.json
│   └── ...
├── logs/              # Logs de operaciones
│   └── quarantine.log
└── index.json         # Índice de cuarentena
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `threat_detected` - Amenaza crítica detectada
- `quarantine_requested` - Solicitud manual de cuarentena
- `restore_requested` - Solicitud de restauración de archivo
- `cleanup_requested` - Solicitud de limpieza de cuarentena

### **Eventos Publicados:**
- `file_quarantined` - Archivo puesto en cuarentena exitosamente
- `quarantine_failed` - Error en proceso de cuarentena
- `file_restored` - Archivo restaurado desde cuarentena
- `restore_failed` - Error en restauración de archivo
- `quarantine_cleaned` - Limpieza automática ejecutada

### **Estructura de Eventos:**
```python
{
  "event_type": "file_quarantined",
  "timestamp": "2024-11-08T15:30:45",
  "quarantine_info": {
    "quarantine_id": "QTN_20241108_001",
    "original_path": "C:\\Downloads\\malware.exe",
    "file_size": 2048576,
    "file_hash": "sha256:abc123...",
    "quarantine_reason": "Keylogger detected by ML detector",
    "detection_confidence": 0.95,
    "encrypted": true
  },
  "metadata": {
    "original_permissions": "755",
    "creation_time": "2024-11-08T10:15:30",
    "modification_time": "2024-11-08T15:20:15",
    "backup_created": true
  }
}
```

## 🚀 **Uso del Plugin**

### Cuarentena Automática
```python
# El plugin se activa automáticamente cuando detectores
# publican eventos threat_detected con nivel CRITICAL o EMERGENCY
engine.activate_category('handlers')
```

### Uso Programático
```python
# Cuarentena manual
quarantine_handler = QuarantineHandlerPlugin()
quarantine_id = quarantine_handler.quarantine_file(
    file_path="C:\\Temp\\suspicious.exe",
    reason="Manual quarantine by user",
    threat_info={
        "detector": "manual",
        "confidence": 1.0,
        "threat_type": "suspected_malware"
    }
)

# Verificar si archivo está en cuarentena
is_quarantined = quarantine_handler.is_file_quarantined(file_path)

# Restaurar archivo
success = quarantine_handler.restore_file(
    quarantine_id=quarantine_id,
    restore_path="C:\\Restored\\suspicious.exe"  # Opcional
)
```

## 📈 **Métricas y Estadísticas**

### Métricas de Cuarentena
```python
quarantine_stats = {
    'total_files_quarantined': 0,    # Total de archivos en cuarentena
    'active_quarantine_files': 0,    # Archivos actualmente en cuarentena
    'files_restored': 0,             # Archivos restaurados exitosamente
    'files_auto_deleted': 0,         # Archivos eliminados automáticamente
    'quarantine_size_mb': 0.0,       # Tamaño total de cuarentena
    'average_quarantine_time_hours': 0.0, # Tiempo promedio en cuarentena
    'quarantine_operations_failed': 0,     # Operaciones fallidas
    'cleanup_operations': 0          # Limpiezas automáticas ejecutadas
}
```

### Performance del Sistema
- **Tiempo de cuarentena**: < 1 segundo para archivos <100MB
- **Tiempo de restauración**: < 500ms para archivos típicos
- **Overhead de encriptación**: ~10% de tiempo adicional
- **Uso de espacio**: ~5% overhead por metadatos y encriptación

## 🔐 **Seguridad de Cuarentena**

### Encriptación de Archivos
```python
# Los archivos se encriptan para prevenir ejecución accidental
encryption_process = {
    'algorithm': 'AES-256-CBC',
    'key_derivation': 'PBKDF2-SHA256',
    'salt': 'random_per_file',
    'iterations': 100000
}
```

### Metadatos Preservados
```json
{
  "quarantine_id": "QTN_20241108_001",
  "original_path": "C:\\Downloads\\malware.exe",
  "original_name": "malware.exe", 
  "file_size": 2048576,
  "file_hash_sha256": "abc123def456...",
  "file_hash_md5": "789xyz012...",
  "quarantine_timestamp": "2024-11-08T15:30:45",
  "detection_info": {
    "detector": "keylogger_detector",
    "confidence": 0.95,
    "threat_type": "Keylogger",
    "detection_method": "behavior_analysis"
  },
  "file_metadata": {
    "creation_time": "2024-11-08T10:15:30",
    "modification_time": "2024-11-08T15:20:15",
    "access_time": "2024-11-08T15:25:00",
    "permissions": "644",
    "owner": "user123",
    "file_type": "PE32 executable"
  }
}
```

## 🧹 **Limpieza Automática**

### Políticas de Limpieza
```python
cleanup_policies = {
    'by_age': {
        'delete_after_days': 30,
        'warn_after_days': 25,
        'check_interval_hours': 24
    },
    'by_size': {
        'max_quarantine_size_gb': 5.0,
        'delete_oldest_first': True,
        'emergency_threshold_gb': 8.0
    },
    'by_type': {
        'keep_high_confidence': True,  # Archivos con confianza >95%
        'delete_test_files': True,     # Archivos de testing
        'preserve_user_quarantined': True  # Cuarentena manual
    }
}
```

### Proceso de Limpieza
1. **Evaluación**: Identifica archivos candidatos para eliminación
2. **Notificación**: Informa al usuario sobre limpieza pendiente
3. **Backup de metadatos**: Preserva información para auditoría
4. **Eliminación segura**: Borrado criptográfico de archivos
5. **Actualización de índices**: Mantiene consistencia del sistema

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Test unitario completo
python -m pytest plugins/handlers/quarantine_handler/

# Test manual de cuarentena
cd plugins/handlers/quarantine_handler
python plugin.py --test-quarantine

# Test de restauración
python plugin.py --test-restore

# Simulación de limpieza automática
python plugin.py --test-cleanup

# Verificar integridad de cuarentena
python plugin.py --verify-integrity
```

### Debugging y Administración
```python
# Listar archivos en cuarentena
quarantined_files = quarantine_handler.list_quarantined_files()
for file_info in quarantined_files:
    print(f"ID: {file_info['id']}, Path: {file_info['original_path']}")

# Verificar integridad de archivo específico
integrity_ok = quarantine_handler.verify_file_integrity(quarantine_id)

# Forzar limpieza manual
cleaned_count = quarantine_handler.force_cleanup(dry_run=False)

# Estadísticas detalladas
stats = quarantine_handler.get_detailed_statistics()
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **Cuarentena Falla por Permisos**
```
Causa: Permisos insuficientes para mover/encriptar archivo
Solución:
- Ejecutar antivirus como administrador
- Verificar permisos en directorio de cuarentena
- Comprobar que archivo no esté en uso por otro proceso
```

#### **Restauración Falla**
```
Causa: Archivo original sobrescrito o permisos incorrectos
Solución:
- Verificar que ruta de destino esté disponible
- Comprobar permisos de escritura en directorio de destino
- Usar path diferente para restauración
- Verificar integridad del archivo en cuarentena
```

#### **Cuarentena Llena**
```
Causa: Límite de tamaño o cantidad de archivos excedido
Solución:
- Ejecutar limpieza manual: python plugin.py --force-cleanup
- Aumentar max_quarantine_size_gb en configuración
- Reducir max_quarantine_days para limpieza más frecuente
- Revisar archivos grandes innecesarios en cuarentena
```

### Recuperación de Desastres
```python
# Reconstruir índice de cuarentena desde metadatos
quarantine_handler.rebuild_index()

# Verificar y reparar archivos corruptos
quarantine_handler.verify_and_repair_quarantine()

# Migrar cuarentena a nueva ubicación
quarantine_handler.migrate_quarantine('/new/path')
```

## 📚 **Integración con el Sistema**

### Flujo de Cuarentena Automática
1. **Detector** identifica amenaza crítica
2. **Event Bus** distribuye `threat_detected` con level CRITICAL/EMERGENCY
3. **Quarantine Handler** evalúa si debe proceder automáticamente
4. **Backup**: Crea copia de seguridad del archivo original
5. **Encriptación**: Encripta archivo y lo mueve a cuarentena
6. **Metadatos**: Guarda información completa del archivo
7. **Notificación**: Informa al usuario sobre cuarentena exitosa
8. **Índice**: Actualiza índice de cuarentena

### Integración con Alert Manager
```python
# Notificaciones automáticas sobre cuarentena
quarantine_alerts = {
    'file_quarantined': 'INFO',
    'quarantine_failed': 'WARNING', 
    'quarantine_full': 'CRITICAL',
    'cleanup_executed': 'INFO'
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🚨 Sistema de Handlers](../README.md)** - Documentación de handlers
- **[🚨 Alert Manager](../alert_manager/README.md)** - Sistema de alertas
- **[📝 Logger Handler](../logger_handler/README.md)** - Sistema de logging
- **[🔍 Detectores](../../detectors/README.md)** - Detectores que generan cuarentena
- **[📊 Core Engine](../../../core/README.md)** - Event Bus para eventos de cuarentena
- **[⚙️ Configuración](../../../config/README.md)** - Configuración de seguridad
- **[📝 Logs](../../../logs/README.md)** - Logs de operaciones de cuarentena

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Cuarentena Segura**