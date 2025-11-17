# 🎯 Behavior Detector Plugin

Plugin especializado en **detección heurística** de comportamientos típicos de keyloggers mediante análisis de patrones.

## 🎯 **Funcionalidades**

### ✅ **Análisis Heurístico**
- **Patrones de procesos** sospechosos por nombre y cmdline
- **Comportamientos específicos** de keyloggers detectados
- **Lista blanca** configurable de procesos confiables
- **Puntuación de riesgo** basada en múltiples indicadores

### 🔍 **Tipos de Análisis**
- **Process Behavior**: Nombres, comandos, APIs sospechosas
- **Network Behavior**: Patrones de exfiltración y C&C
- **File Behavior**: Acceso a credenciales y logs
- **System Behavior**: Modificaciones de registro y persistencia

### 📊 **Indicadores de Amenaza**
- Patrones de nombres de proceso (`.*keylog.*`, `.*stealer.*`)
- APIs de Windows peligrosas (`SetWindowsHookEx`, `GetAsyncKeyState`)
- Comunicaciones de red sospechosas
- Accesos a archivos de credenciales

## 🏗️ **Patrones de Diseño**

### **Template Method Pattern**
- Hereda ciclo de vida de `BasePlugin`
- Métodos especializados: `_analyze_process_behavior()`, `_analyze_network_behavior()`

### **Strategy Pattern**
- Múltiples estrategias de análisis según tipo de datos
- Algoritmos intercambiables: heurística vs reglas vs ML

### **Observer Pattern**
- Recibe eventos `process_data_available`, `network_data_available`
- Publica `threat_detected` cuando encuentra patrones

### **Rule Engine Pattern**
- Motor de reglas configurable para detección
- Reglas dinámicas cargadas desde configuración

## 📁 **Archivos del Plugin**

```
behavior_detector/
├── plugin.py          # BehaviorDetectorPlugin principal
├── behavior_engine.py # Motor de análisis heurístico
├── rule_engine.py     # Motor de reglas configurable  
├── whitelist_manager.py # Gestor de lista blanca
├── config.json        # Configuración del plugin
├── __init__.py        # Auto-registro
└── README.md          # Esta documentación
```

## ⚙️ **Configuración**

```json
{
  "behavior_config": {
    "risk_threshold": 0.7,
    "enable_whitelist": true,
    "enable_advanced_analysis": true
  },
  "detection_rules": {
    "process_patterns": [".*keylog.*", ".*stealer.*"],
    "suspicious_apis": ["SetWindowsHookEx", "GetAsyncKeyState"],
    "file_patterns": [".*passwords?.txt$", ".*\.keylog$"]
  },
  "whitelist": {
    "allowed_processes": ["notepad.exe", "explorer.exe"],
    "trusted_directories": ["%PROGRAMFILES%", "%WINDIR%"]
  }
}
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `process_data_available` - Nuevos datos de procesos
- `network_data_available` - Actividad de red para analizar
- `file_access_data` - Accesos al sistema de archivos
- `scan_requested` - Solicitud de escaneo heurístico

### **Eventos Publicados:**
- `threat_detected` - Comportamiento sospechoso detectado
- `behavior_analysis_completed` - Análisis heurístico finalizado
- `whitelist_violation` - Proceso no confiable detectado
- `high_risk_behavior` - Comportamiento de alto riesgo

## 🚀 **Uso**

### **Activación automática:**
```python
# Se activa con categoría 'detectors'
engine.activate_category('detectors')
```

### **Análisis manual:**
```python
behavior_plugin = plugin_manager.create_plugin('behavior_detector')
threats = behavior_plugin.analyze_processes(process_list)
```

## 📈 **Métricas**

- **analyses_performed**: Total de análisis realizados
- **threats_detected**: Comportamientos sospechosos detectados
- **patterns_matched**: Reglas/patrones que coincidieron  
- **whitelisted_processes**: Procesos permitidos ignorados
- **avg_analysis_time**: Tiempo promedio de análisis
- **risk_scores_calculated**: Puntuaciones de riesgo calculadas

## 🎛️ **Reglas de Detección**

### **Process Behavior:**
- `.*keylog.*` - Nombres de proceso típicos de keyloggers
- `.*spyware.*`, `.*stealer.*` - Malware conocido
- `.*hook.*keyboard.*` - Comandos sospechosos
- APIs: `SetWindowsHookEx`, `RegisterRawInputDevices`

### **Network Behavior:**
- Subidas frecuentes de datos pequeños (exfiltración)
- Comunicaciones encriptadas no estándar
- Beacons periódicos a servidores C&C
- Uso de puertos no estándar

### **File Behavior:**  
- Acceso a archivos `passwords.txt`, `credentials.txt`
- Creación de archivos `.keylog`, `.dat`
- Escritura en directorios temporales
- Encriptación de archivos de logs

### **System Behavior:**
- Modificaciones en registro de startup
- Inyección de procesos
- Bypass de sistemas de seguridad
- Persistencia en el sistema

## 🔧 **Lista Blanca**

### **Procesos Confiables:**
```json
{
  "allowed_processes": [
    "explorer.exe", "notepad.exe", "chrome.exe",
    "firefox.exe", "outlook.exe", "teams.exe"
  ]
}
```

### **Directorios Confiables:**
```json
{
  "trusted_directories": [
    "%PROGRAMFILES%", "%PROGRAMFILES(X86)%", 
    "%WINDIR%", "%SYSTEM32%"
  ]
}
```

## 🧪 **Testing**

### **Test del plugin:**
```bash
cd plugins/detectors/behavior_detector
python plugin.py --test
```

### **Test con datos sintéticos:**
```bash  
python plugin.py --test-processes
```

## 🔧 **Troubleshooting**

### **Falsos positivos:**
- Ajustar `risk_threshold` en configuración
- Agregar procesos legítimos a whitelist
- Revisar patrones de detección muy amplios

### **Detecciones perdidas:**
- Reducir `risk_threshold`  
- Agregar nuevos patrones sospechosos
- Verificar que eventos lleguen correctamente

### **Performance:**
- Limitar análisis a procesos críticos
- Usar whitelist para filtrar procesos conocidos
- Ajustar frecuencia de análisis

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🧠 Recursos Compartidos](../../shared/README.md)** - Motor de inteligencia unificado
- **[🤖 ML Detector](../ml_detector/README.md)** - Detector de machine learning
- **[🌐 Network Detector](../network_detector/README.md)** - Detector de red
- **[⌨️ Keylogger Detector](../keylogger_detector/README.md)** - Detector especializado
- **[⚙️ Configuración](../../../config/README.md)** - Configuración del sistema
- **[📊 Core Engine](../../../core/README.md)** - Motor principal

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Detección Profesional**