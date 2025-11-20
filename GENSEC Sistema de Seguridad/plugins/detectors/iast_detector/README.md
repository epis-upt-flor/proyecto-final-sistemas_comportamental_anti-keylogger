# IAST Self-Protection & Keylogger Detector

## 🛡️ **Descripción General**

El **IAST Detector** es un plugin especializado que implementa **Interactive Application Security Testing** para:

1. **🔒 Auto-protección del Antivirus**: Monitorea la integridad de archivos críticos del sistema antivirus
2. **🎯 Detección Especializada de Keyloggers**: Usa análisis híbrido (SAST + DAST) para identificar keyloggers
3. **📊 Logging No-Invasivo**: Solo genera logs, NO modifica código existente

## 🏗️ **Arquitectura**

```
iast_detector/
├── iast_engine.py      # Motor principal IAST
├── plugin.py          # Wrapper del plugin
├── config.json        # Configuración
└── README.md         # Este archivo
```

## 🔍 **Capacidades de Detección**

### **1. Protección del Antivirus**
- Calcula hashes baseline de archivos críticos
- Detecta modificaciones no autorizadas
- Monitorea integridad en tiempo real
- Alerta sobre intentos de tampering

### **2. Detección de Keyloggers**
- **SAST (Static Analysis)**: Analiza nombres, rutas, parámetros
- **DAST (Dynamic Analysis)**: Monitorea CPU, conexiones, archivos
- **IAST (Interactive)**: Combina ambos análisis inteligentemente
- **Scoring System**: Sistema de puntuación para reducir falsos positivos

## ⚙️ **Configuración**

```json
{
  "settings": {
    "monitoring_enabled": true,
    "scan_interval": 30,
    "detection_threshold": 0.7,
    "static_weight": 0.6,
    "dynamic_weight": 0.4
  }
}
```

## 🚀 **Instalación y Uso**

### **1. Testing Independiente**
```bash
cd plugins/detectors/iast_detector
python iast_engine.py
```

### **2. Integración con Antivirus**
```python
# El plugin se registra automáticamente
# No requiere modificaciones de código
```

### **3. Logs Generados**
```json
{
  "event_type": "KEYLOGGER_DETECTION",
  "severity": "CRITICAL", 
  "details": {
    "process": "suspicious.exe",
    "pid": 1234,
    "total_score": 0.85
  }
}
```

## 📊 **Métricas de Detección**

| Análisis | Peso | Criterios |
|----------|------|-----------|
| **SAST** | 60% | Nombres sospechosos, ubicaciones, parámetros |
| **DAST** | 40% | CPU usage, conexiones, archivos abiertos |
| **Threshold** | 0.7 | Umbral de detección configurable |

## 🎯 **Casos de Uso**

### **Escenario 1: Protección del Antivirus**
```
1. Usuario/malware intenta modificar core/engine.py
2. IAST detecta cambio en hash SHA256
3. Log: "ANTIVIRUS_INTEGRITY_COMPROMISED"
4. Sistema alerta administrador
```

### **Escenario 2: Keylogger Detection**
```
1. Proceso "winlogger.exe" inicia desde %TEMP%
2. SAST: Score 0.5 (nombre + ubicación sospechosa)  
3. DAST: Score 0.8 (conexiones + archivos .log)
4. IAST: Score final 0.62 → DETECTADO
5. Log: "KEYLOGGER_DETECTION" con detalles
```

## 🔐 **Beneficios de Seguridad**

1. **Zero-Touch**: No modifica código existente
2. **Self-Protection**: Protege la integridad del antivirus
3. **Specialized Detection**: Enfocado en keyloggers
4. **Hybrid Analysis**: Combina múltiples técnicas
5. **Structured Logging**: Integración con sistema web
6. **Configurable**: Thresholds ajustables

## 📈 **Próximas Mejoras**

- [ ] Integración con threat intelligence feeds
- [ ] Machine learning para mejorar detección
- [ ] Análisis de comportamiento de red
- [ ] Correlación con otros detectores
- [ ] Dashboard específico para IAST

## 🧪 **Testing**

```python
# Test básico
python plugin.py

# Test motor IAST
python iast_engine.py

# Verificar integración
# Ejecutar antivirus y revisar logs
```

## 📝 **Logs de Ejemplo**

```json
{
  "timestamp": "2024-11-08T15:30:45",
  "level": "ERROR", 
  "message": "🚨 EVENTO DE SEGURIDAD: KEYLOGGER_DETECTION",
  "details": {
    "pid": 1234,
    "name": "suspicious_app.exe",
    "total_score": 0.85,
    "static_score": 0.6,
    "dynamic_score": 0.8
  }
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🧠 Recursos Compartidos](../../shared/README.md)** - Motor de inteligencia unificado
- **[🎯 Behavior Detector](../behavior_detector/README.md)** - Detector de comportamiento
- **[⌨️ Keylogger Detector](../keylogger_detector/README.md)** - Detector especializado de keyloggers
- **[🤖 ML Detector](../ml_detector/README.md)** - Detector con machine learning
- **[🌐 Network Detector](../network_detector/README.md)** - Detector de red
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración
- **[📊 Core Engine](../../../core/README.md)** - Motor principal protegido
- **[📝 Logs](../../../logs/README.md)** - Sistema de logging

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Auto-Protección y Detección IAST Avanzada**