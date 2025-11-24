# 🔬 GENSEC: Framework de Análisis Forense de Comportamiento (Sandbox)

## 📋 Descripción General

**GENSEC** es una plataforma forense especializada en el **monitoreo de comportamiento (TTPs)** y **generación de evidencia forense** de procesos en entornos sandbox. El framework está diseñado para analizar, documentar y evaluar patrones de comportamiento sospechoso mediante técnicas avanzadas de consenso y ponderación algorítmica.

### 🎯 Propósito Principal
Proporcionar análisis forense profundo de comportamientos de procesos mediante la observación de **Técnicas, Tácticas y Procedimientos (TTPs)** para la generación de **reportes forenses estructurados** en formato JSON.

---

## 🏗️ Arquitectura del Sistema

### Componentes Principales

#### 1. **Motor de Consenso** ⚖️
- **Ponderación inteligente**: ML Detector tiene prioridad (Peso 0.7) sobre análisis heurístico
- **Lógica de Veto**: Permite autocorrección anulando falsos positivos del Keylogger Detector
- **Scoring unificado**: Combina múltiples fuentes de análisis en una puntuación final

#### 2. **Event Bus Asíncrono** 🔄
- **Comunicación desacoplada**: Los plugins se comunican mediante eventos
- **Procesamiento concurrente**: Manejo asíncrono de múltiples análisis simultáneos
- **Escalabilidad**: Permite agregar nuevos detectores sin modificar el núcleo

#### 3. **Sistema de Plugins** 🧩
- **Detectores especializados**: ML, Keylogger, Behavior, Network, IAST
- **Monitores en tiempo real**: Process, File, Network
- **Handlers forenses**: Logger, Alert Manager, Quarantine

---

## 🔄 Flujo de Funcionamiento

### Fase 1: Inicialización del Sandbox
```
[Sistema de Plugins] → [Event Bus] → [Motor de Consenso]
        ↓
[Descubrimiento automático de plugins]
        ↓
[Carga y activación de detectores]
        ↓
[Configuración de monitores en tiempo real]
```

### Fase 2: Monitoreo de TTPs
```
[Captura de comportamiento] → [Event Bus] → [Análisis multidetector]
        ↓
[Ponderación por consenso (ML prioritario)]
        ↓
[Aplicación de lógica de veto (autocorrección)]
        ↓
[Generación de evidencia forense]
```

### Fase 3: Controles de Sandbox
```
[Identificación de amenaza] → [Controles de prueba]
        ├─ End Test: Terminación controlada de procesos
        ├─ Isolate: Aislamiento de muestras sospechosas
        └─ Forensic Analysis: Análisis detallado de comportamiento
```

---

## 🔍 Características Forenses Únicas

### **Ponderación del Consenso**
- **ML Detector (Peso 0.7)**: Modelo de machine learning con prioridad sobre heurísticas tradicionales
- **Heuristic Analysis (Peso 0.3)**: Análisis basado en reglas como complemento
- **Scoring transparente**: Cada detección incluye breakdown de puntuaciones individuales

### **Lógica de Veto Inteligente**
- **Autocorrección**: Sistema capaz de anular falsos positivos automáticamente
- **Keylogger Detector Override**: Casos específicos donde la lógica heurística puede ser vetada por ML
- **Calibración continua**: Mejora progresiva de la precisión del sistema

### **Controles de Prueba en Sandbox**
- **End Test**: Terminación controlada para evaluar comportamiento post-terminación
- **Isolate**: Cuarentena forense preservando integridad de evidencia
- **Forensic Actions**: Conjunto completo de herramientas de análisis forense

---

## 📊 Productos de Análisis

### **Reporte Forense Estructurado (JSON)**
Cada análisis genera un reporte completo que incluye:

```json
{
  "forensic_report": {
    "timestamp": "2025-11-24T15:42:15Z",
    "sample_info": {
      "pid": 1234,
      "process_name": "suspicious_process.exe",
      "path": "C:\\temp\\suspicious_process.exe",
      "command_line": "suspicious_process.exe --stealth"
    },
    "ttp_analysis": {
      "techniques_observed": [
        "T1056.001 - Input Capture: Keylogging",
        "T1055 - Process Injection",
        "T1027 - Obfuscated Files"
      ],
      "behavior_patterns": [
        "keyboard_monitoring",
        "stealth_execution",
        "data_exfiltration_attempt"
      ]
    },
    "consensus_scoring": {
      "ml_detector": {
        "score": 0.85,
        "weight": 0.7,
        "weighted_contribution": 0.595
      },
      "heuristic_analysis": {
        "score": 0.40,
        "weight": 0.3,
        "weighted_contribution": 0.12
      },
      "final_score": 0.715,
      "risk_level": "HIGH",
      "veto_applied": false
    },
    "forensic_evidence": {
      "api_calls_monitored": 247,
      "suspicious_apis": [
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "CreateRemoteThread"
      ],
      "network_connections": [],
      "file_operations": [
        "CREATE: C:\\temp\\keylog.txt",
        "WRITE: 1247 bytes encrypted data"
      ]
    }
  }
}
```

---

## 🚀 Instalación y Configuración

### Prerrequisitos
```bash
# Python 3.8+
pip install -r requirements.txt

# Dependencias principales:
# - psutil (monitoreo de procesos)
# - onnxruntime (ML inference)
# - dearpygui (interfaz forense)
# - numpy, pandas (análisis de datos)
```

### Configuración del Sandbox
```bash
# Configuración automática
python install_dependencies.py

# Registro de plugins
python register_plugins.py

# Validación de configuración
python -m config.config_validator
```

### Ejecución del Framework
```bash
# Modo sandbox completo
python production_launcher.py

# Solo backend de análisis
python backend_launcher.py

# Interfaz de análisis forense
cd frontend && python main.py
```

---

## ⚙️ Configuración de Análisis

### **Configuración del Motor de Consenso**
```toml
[consensus_engine]
ml_detector_weight = 0.7
heuristic_weight = 0.3
veto_threshold = 0.85
auto_correction = true

[sandbox_controls]
enable_end_test = true
enable_isolation = true
preserve_forensic_evidence = true
auto_report_generation = true
```

### **Configuración de TTPs**
```json
{
  "ttp_monitoring": {
    "mitre_attack_mapping": true,
    "behavior_patterns": [
      "keyboard_capture",
      "process_injection",
      "persistence_mechanisms",
      "defense_evasion"
    ],
    "evidence_collection": {
      "api_monitoring": true,
      "memory_analysis": false,
      "network_traffic": true,
      "file_system_changes": true
    }
  }
}
```

---

## 📈 Casos de Uso Forense

### **Análisis de Malware**
- Observación de comportamiento en sandbox controlado
- Identificación de TTPs específicos de familias de malware
- Generación de IOCs (Indicators of Compromise)

### **Investigación de Incidentes**
- Análisis retrospectivo de procesos sospechosos
- Correlación de eventos mediante Event Bus
- Reconstrucción de cadena de ataques

### **Desarrollo de Firmas**
- Calibración de pesos del motor de consenso
- Validación de lógica de veto
- Mejora continua de detectores ML

---

## 🔧 Arquitectura de Plugins

### **Detectores Especializados**
- **ML Detector**: Análisis mediante redes neuronales ONNX
- **Keylogger Detector**: Detección específica de captura de teclado
- **Behavior Detector**: Análisis heurístico de patrones
- **IAST Detector**: Interactive Application Security Testing
- **Network Detector**: Análisis de comunicaciones sospechosas

### **Sistema de Eventos**
```python
# Ejemplo de comunicación asíncrona
@event_handler('process_created')
def analyze_new_process(event_data):
    # Múltiples detectores procesan el mismo evento
    ml_score = ml_detector.analyze(event_data)
    heuristic_score = behavior_detector.analyze(event_data)
    
    # Motor de consenso combina resultados
    final_assessment = consensus_engine.evaluate(
        ml_score, heuristic_score
    )
```

---

## 📋 Logs y Monitoreo

### **Estructura de Logs Forenses**
```
logs/
├── forensic_analysis.log     # Análisis principal
├── consensus_engine.log      # Decisiones de consenso
├── ttp_detection.log        # TTPs identificados
├── event_bus.log            # Comunicación entre plugins
└── sandbox_controls.log     # Acciones de control ejecutadas
```

### **Métricas de Rendimiento**
- Latencia promedio de análisis: <2 segundos
- Throughput de eventos: 1000+ eventos/minuto
- Precisión del consenso: 94.2% (con lógica de veto)
- Falsos positivos: <3% (post-autocorrección)

---

## 📚 Documentación Técnica

### **Arquitectura Detallada**
- [Diagrama de Componentes](doc/DIAGRAMA_ARQUITECTURA.md)
- [Análisis de Consenso](doc/analysis_mejoras_detector.md)
- [Integración MDSD](doc/MDSD_Integration_Plan.md)

### **Guías de Desarrollo**
- [Framework de Testing TDD](tests/GUIA_IMPLEMENTACION_TDD.md)
- [Análisis de Mejores Prácticas](doc/ANALISIS_MEJORES_TESTS_TDD.md)
- [Metodologías Ágiles](doc/FORMATO_7_METODOLOGIAS_AGILES.md)

### **Especificaciones Técnicas**
- [Motor de Consenso](core/consensus_engine.py)
- [Event Bus Asíncrono](core/event_bus.py)
- [Sistema de Plugins](core/plugin_manager.py)

---

## 🤝 Contribución

### **Desarrollo de Plugins**
1. Heredar de `BasePlugin`
2. Implementar interfaz de análisis forense
3. Registrar eventos en Event Bus
4. Configurar ponderación en motor de consenso

### **Mejora del Consenso**
1. Calibrar pesos basados en datasets de validación
2. Implementar nuevas lógicas de veto
3. Optimizar autocorrección de falsos positivos

---

## 📄 Licencia y Uso

**GENSEC Framework de Análisis Forense** está diseñado para uso en investigación de ciberseguridad, análisis forense y desarrollo de capacidades de detección avanzadas.

---

*Framework desarrollado para análisis comportamental avanzado y generación de evidencia forense - v2.1.0*