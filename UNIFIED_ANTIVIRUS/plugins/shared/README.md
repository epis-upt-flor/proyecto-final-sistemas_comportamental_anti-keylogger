# 🧠 Recursos Compartidos de Plugins

## Descripción General

Directorio que contiene recursos, librerías y utilidades compartidas entre todos los plugins del sistema. Proporciona funcionalidades comunes y sistemas de inteligencia unificados.

## 📁 Contenido

```
shared/
└── unified_intelligence.py    # Motor de inteligencia unificado
```

## 🎯 Unified Intelligence Engine

### Propósito
Sistema unificado de inteligencia que reemplaza patrones simples con análisis comportamental avanzado. Proporciona inteligencia centralizada para todos los detectores.

### Funcionalidades Principales

#### 🕵️ **Análisis de Enmascaramiento**
Detecta procesos que intentan imitar software legítimo:

```python
# Nombres que imitan procesos del sistema
system_mimics = ["svchost", "csrss", "winlogon", "lsass", "explorer"]

# Nombres que imitan navegadores
browser_mimics = ["chrome", "firefox", "edge", "opera"]

# Nombres que imitan antivirus
security_mimics = ["windows defender", "avast", "norton", "kaspersky"]
```

#### 📍 **Ubicaciones Furtivas**
Identifica ubicaciones comúnmente usadas por malware:

```python
# Ubicaciones de alta sospecha
high_stealth_locations = [
    "windows\\fonts",
    "windows\\system32\\spool\\drivers", 
    "programdata\\microsoft\\windows defender",
    "users\\public\\documents\\shared"
]
```

#### 🎯 **Patrones de Comportamiento**
Analiza comportamientos típicos de amenazas:

- **Persistencia**: Métodos de auto-arranque
- **Comunicación**: Patrones de red sospechosos
- **Archivos**: Manipulación de archivos críticos
- **Procesos**: Inyección y hooking

## 🔧 API del Motor de Inteligencia

### Métodos Principales

#### `analyze_process_masquerading(process_info)`
Detecta intentos de enmascaramiento de procesos.

**Parámetros**:
- `process_info`: Información del proceso (nombre, ubicación, etc.)

**Retorna**:
- `risk_score`: Puntuación de riesgo (0-100)
- `masquerading_type`: Tipo de enmascaramiento detectado
- `confidence`: Nivel de confianza del análisis

#### `check_stealth_location(file_path)`
Evalúa si una ubicación es comúnmente usada por malware.

**Parámetros**:
- `file_path`: Ruta del archivo a evaluar

**Retorna**:
- `stealth_level`: Nivel de sigilo (high/medium/low)
- `risk_indicators`: Lista de indicadores de riesgo
- `legitimate_reasons`: Razones legítimas para estar ahí

#### `analyze_behavior_pattern(behavior_data)`
Analiza patrones de comportamiento para detectar actividad maliciosa.

**Parámetros**:
- `behavior_data`: Datos del comportamiento observado

**Retorna**:
- `threat_probability`: Probabilidad de amenaza
- `behavior_type`: Tipo de comportamiento detectado
- `mitigation_suggestions`: Sugerencias de mitigación

## 🧮 Algoritmos de Inteligencia

### Análisis Heurístico
- **Entropía de nombres**: Detecta nombres generados aleatoriamente
- **Análisis de ubicación**: Evalúa contexto de ubicación de archivos
- **Patrones temporales**: Detecta comportamientos temporales sospechosos

### Machine Learning Integrado
- **Clasificación de comportamiento**: Modelos pre-entrenados
- **Análisis de similitud**: Comparación con amenazas conocidas
- **Detección de anomalías**: Identificación de comportamientos atípicos

## 🔄 Integración con Detectores

### Uso desde Detectores
```python
from plugins.shared.unified_intelligence import UnifiedIntelligenceEngine

# Inicializar motor de inteligencia
intelligence = UnifiedIntelligenceEngine()

# Analizar proceso sospechoso
process_analysis = intelligence.analyze_process_masquerading(process_info)

if process_analysis['risk_score'] > 70:
    # Procesar como amenaza potencial
    handle_potential_threat(process_info, process_analysis)
```

### Eventos del Sistema
El motor se integra con el Event Bus para:
- Recibir datos de comportamiento en tiempo real
- Proporcionar análisis a múltiples detectores
- Mantener estado de amenazas conocidas

## 📊 Métricas y Monitoreo

### Estadísticas del Motor
- **Análisis realizados**: Contador de análisis ejecutados
- **Amenazas detectadas**: Número de amenazas identificadas
- **Falsos positivos**: Métricas de precisión
- **Tiempo de respuesta**: Performance del análisis

### Logs de Inteligencia
```
[INFO] Process masquerading detected: fake_svchost.exe (risk: 85%)
[WARN] Stealth location access: windows\\fonts\\malware.exe
[DEBUG] Behavior pattern analysis: keylogging signature detected
```

## 🔧 Configuración

### Parámetros Ajustables
```json
{
  "sensitivity_level": "medium",
  "masquerading_threshold": 70,
  "stealth_location_weight": 1.5,
  "behavior_analysis_timeout": 5000,
  "machine_learning_enabled": true
}
```

### Actualizaciones de Inteligencia
- **Fuentes de threat intelligence**: IOCs, YARA rules, etc.
- **Actualización automática**: Nuevos patrones y signatures
- **Aprendizaje continuo**: Mejora basada en detecciones

## 🛠️ Mantenimiento

### Actualización de Patrones
El sistema actualiza automáticamente:
- Nuevas técnicas de enmascaramiento
- Ubicaciones furtivas emergentes
- Patrones de comportamiento actualizados
- Firmas de amenazas conocidas

### Optimización
- **Cache de análisis**: Resultados frecuentes se cachean
- **Análisis paralelo**: Múltiples hilos para mejor performance
- **Gestión de memoria**: Limpieza automática de datos antiguos

## 📋 Enlaces Relacionados

- **[Behavior Detector](../detectors/behavior_detector/README.md)** - Usa análisis de comportamiento
- **[ML Detector](../detectors/ml_detector/README.md)** - Integración con machine learning
- **[Keylogger Detector](../detectors/keylogger_detector/README.md)** - Aplica inteligencia especializada
- **[Core Engine](../../core/README.md)** - Motor principal del sistema

---

**Nota**: Este motor de inteligencia es el cerebro compartido del sistema de detección, proporcionando análisis avanzado y reduciendo falsos positivos mediante técnicas heurísticas sofisticadas.