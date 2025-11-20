# 🧠 ML Detector Plugin

Plugin especializado en detección de keyloggers usando **Machine Learning** con modelos ONNX optimizados.

## 🎯 **Funcionalidades**

### ✅ **Detección por ML**
- **Modelos ONNX** para predicciones en tiempo real
- **Fallback sklearn** si ONNX no está disponible  
- **81 características** extraídas de flujos de red
- **Threshold configurable** de confianza

### 📊 **Análisis de Flujos**
- Extracción automática de características de red
- Análisis agregado por conexión (src/dst IP:puerto)
- Predicciones con probabilidades de confianza
- Estadísticas detalladas de rendimiento

### 🔬 **Características Técnicas**
- **209MB+ modelos** entrenados con datasets reales
- **Tiempo de predicción** sub-segundo
- **Múltiples clases** de amenazas soportadas
- **Metadata automático** de modelos

## 🏗️ **Patrones de Diseño**

### **Template Method Pattern**
- Hereda ciclo de vida de `BasePlugin`
- Métodos especializados: `_load_model()`, `_extract_features()`

### **Strategy Pattern**  
- Múltiples estrategias: ONNX vs sklearn
- Algoritmos intercambiables según disponibilidad

### **Factory Pattern**
- `ModelFactory` crea instancias según configuración
- Auto-detección de modelos disponibles

### **Observer Pattern**
- Publica eventos `threat_detected` al event bus
- Suscribe a `network_data_available` para análisis

## 📁 **Archivos del Plugin**

```
ml_detector/
├── plugin.py          # MLDetectorPlugin principal
├── ml_engine.py       # Motor ML (ONNX/sklearn)  
├── feature_extractor.py # Extractor de características
├── config.json        # Configuración del plugin
├── __init__.py        # Auto-registro
└── README.md          # Esta documentación
```

## ⚙️ **Configuración**

```json
{
  "ml_config": {
    "model_path": "../../ANTIVIRUS_PRODUCTION/models",
    "use_onnx": true,
    "confidence_threshold": 0.8,
    "prediction_timeout_ms": 5000
  },
  "models": {
    "primary_onnx": "modelo_keylogger_from_datos.onnx", 
    "fallback_sklearn": "rf_large_model_20250918_112442.pkl",
    "label_classes": "label_classes.json"
  }
}
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `network_data_available` - Nuevos datos de red para análisis
- `scan_requested` - Solicitud de escaneo manual
- `config_updated` - Actualización de configuración

### **Eventos Publicados:**
- `threat_detected` - Keylogger detectado por ML
- `ml_analysis_completed` - Análisis ML finalizado
- `model_loaded` - Modelo ML cargado exitosamente
- `prediction_error` - Error en predicción

## 🚀 **Uso**

### **Activación automática:**
```python
# Se activa con categoría 'detectors'
engine.activate_category('detectors')
```

### **Análisis manual:**
```python
ml_plugin = plugin_manager.create_plugin('ml_detector')
threats = ml_plugin.analyze_network_data(network_flows)
```

## 📈 **Métricas**

- **predictions_made**: Total de predicciones realizadas
- **threats_detected**: Amenazas detectadas con alta confianza  
- **avg_prediction_time**: Tiempo promedio de predicción (ms)
- **model_accuracy**: Exactitud del modelo (si disponible)
- **feature_extraction_time**: Tiempo de extracción de características

## 🛠️ **Modelos Soportados**

### **ONNX (Preferido):**
- `modelo_keylogger_from_datos.onnx` - Modelo principal
- `keylogger_model_large_20250918_112840.onnx` - Modelo extendido
- Optimización automática para CPU/GPU

### **sklearn (Fallback):**
- `rf_large_model_20250918_112442.pkl` - Random Forest
- Compatibilidad total con scikit-learn

## 🧪 **Testing**

### **Test del plugin:**
```bash
cd plugins/detectors/ml_detector
python plugin.py --test
```

### **Test con datos sintéticos:**
```bash
python plugin.py --test-synthetic
```

## 🔧 **Troubleshooting**

### **Modelo no carga:**
- Verificar que `models/` contenga archivos ONNX/PKL
- Comprobar `onnxruntime` instalado
- Revisar logs en `logs/ml_detector.log`

### **Predicciones lentas:**
- Reducir `batch_size` en configuración
- Usar modelo sklearn como fallback
- Verificar recursos de CPU/memoria

### **Características incorrectas:**
- Validar `metadata.json` del modelo
- Comprobar formato de datos de red de entrada
- Usar `feature_extractor.py` standalone para debug

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🧠 Recursos Compartidos](../../shared/README.md)** - Motor de inteligencia unificado
- **[🤖 Modelos ML](../../../models/README.md)** - Modelos y metadatos ONNX
- **[🎯 Behavior Detector](../behavior_detector/README.md)** - Detector de comportamiento
- **[⌨️ Keylogger Detector](../keylogger_detector/README.md)** - Detector especializado
- **[🌐 Network Detector](../network_detector/README.md)** - Detector de red
- **[⚙️ Configuración ML](../../../config/README.md)** - Configuración de machine learning
- **[📊 Core Engine](../../../core/README.md)** - Motor principal del sistema

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Detección con IA Avanzada**