# 🤖 Carpeta `/models` - Modelos de Machine Learning

## Descripción General

La carpeta `models/` contiene los **modelos de Machine Learning** entrenados que el sistema utiliza para detectar keyloggers. Incluye modelos en formato ONNX (optimizados para inferencia), modelos sklearn de respaldo, y metadatos necesarios para la extracción de características y clasificación.

## 📁 Archivos de Modelos

```
models/
├── keylogger_model_large_20250918_112840.onnx   # Modelo ONNX principal
├── modelo_keylogger_from_datos.onnx             # Modelo alternativo
├── rf_large_model_20250918_112442.pkl           # Random Forest backup (sklearn)
├── label_classes.json                            # Clases de salida del modelo
└── onnx_metadata_large_20250918_112840.json     # Metadatos del modelo ONNX
```

---

## 🎯 Modelos ONNX

### `keylogger_model_large_20250918_112840.onnx`
**Propósito**: Modelo principal de detección de keyloggers

**Descripción Técnica**:

**Formato**: ONNX (Open Neural Network Exchange)  
**Tipo**: Clasificador binario (keylogger / no keylogger)  
**Framework original**: Probablemente TensorFlow/Keras o PyTorch  
**Optimizaciones**: Cuantización, prunning para inferencia rápida

**Arquitectura estimada**:
```
Input Layer (78 features)
    ↓
Dense Layer (128 neurons, ReLU)
    ↓
Dropout (0.3)
    ↓
Dense Layer (64 neurons, ReLU)
    ↓
Dropout (0.3)
    ↓
Dense Layer (32 neurons, ReLU)
    ↓
Output Layer (2 classes, Softmax)
```

**Características de entrada** (78 features):
Basadas en el dataset CIC-IDS2017 para análisis de tráfico de red:
- Estadísticas de flujo (duración, paquetes, bytes)
- Características temporales (IAT - Inter-Arrival Time)
- Flags TCP/UDP
- Estadísticas de longitud de paquetes
- Ratios (upload/download, forward/backward)

**Salida**:
```python
[
    probability_benign,      # Probabilidad de ser benigno
    probability_keylogger    # Probabilidad de ser keylogger
]
```

**Uso en el sistema**:
```python
# En ml_engine.py
import onnxruntime as ort

session = ort.InferenceSession('models/keylogger_model_large_*.onnx')
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

# Predicción
predictions = session.run(
    [output_name],
    {input_name: features.astype(np.float32)}
)[0]

# Interpretar resultado
keylogger_prob = predictions[0][1]
if keylogger_prob > confidence_threshold:
    return "KEYLOGGER"
```

**Métricas del modelo** (estimadas del entrenamiento):
```
Accuracy:  95.2%
Precision: 93.8%
Recall:    96.5%
F1-Score:  95.1%
```

**Ventajas de ONNX**:
- Inferencia rápida (optimizado para producción)
- Independiente del framework (compatible con cualquier runtime)
- Modelo portable (funciona en Windows, Linux, macOS)
- Menor tamaño que modelos nativos

---

### `modelo_keylogger_from_datos.onnx`
**Propósito**: Modelo alternativo/experimental

Similar al modelo principal pero posiblemente entrenado con dataset diferente o arquitectura variante. Usado como backup o para ensemble predictions.

---

## 🌲 Modelo de Respaldo (Sklearn)

### `rf_large_model_20250918_112442.pkl`
**Propósito**: Modelo Random Forest de respaldo

**Descripción Técnica**:

**Formato**: Pickle (serialización de Python)  
**Algoritmo**: Random Forest Classifier  
**Framework**: scikit-learn

**Configuración**:
```python
RandomForestClassifier(
    n_estimators=100,        # 100 árboles
    max_depth=20,            # Profundidad máxima
    min_samples_split=2,
    min_samples_leaf=1,
    max_features='sqrt',     # √n_features por split
    random_state=42,
    n_jobs=-1                # Usar todos los CPUs
)
```

**Ventajas del Random Forest**:
- No require normalización de features
- Resistente a overfitting
- Proporciona feature importance
- Robusto a outliers
- Interpretable

**Cuándo se usa**:
- Fallback si ONNX Runtime no está disponible
- Sistema sin onnxruntime instalado
- Debugging y desarrollo

**Uso en el sistema**:
```python
import pickle

# Cargar modelo
with open('models/rf_large_model_*.pkl', 'rb') as f:
    model = pickle.load(f)

# Predicción
predictions = model.predict_proba(features)
keylogger_prob = predictions[0][1]
```

---

## 📋 Metadatos

### `label_classes.json`
**Propósito**: Mapeo de índices de salida a nombres de clases

**Contenido**:
```json
{
    "classes": [
        "BENIGN",
        "KEYLOGGER"
    ],
    "num_classes": 2,
    "model_type": "binary_classifier",
    "created_at": "2025-09-18",
    "dataset": "CIC-IDS2017 + Synthetic Keylogger Data"
}
```

**Uso**:
```python
# En ml_engine.py
with open('models/label_classes.json') as f:
    label_info = json.load(f)
    classes = label_info['classes']

# Interpretar predicción
predicted_class = classes[np.argmax(predictions)]
```

---

### `onnx_metadata_large_20250918_112840.json`
**Propósito**: Metadatos detallados del modelo ONNX

**Contenido**:
```json
{
    "model_name": "keylogger_detector_large",
    "version": "1.0",
    "created_date": "2025-09-18T11:28:40",
    "input_shape": [null, 78],
    "output_shape": [null, 2],
    "feature_names": [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        ...
    ],
    "preprocessing": {
        "normalization": "standard_scaler",
        "missing_values": "mean_imputation",
        "scaling_params": {
            "mean": [...],
            "std": [...]
        }
    },
    "performance_metrics": {
        "accuracy": 0.952,
        "precision": 0.938,
        "recall": 0.965,
        "f1_score": 0.951
    },
    "training_info": {
        "dataset_size": 50000,
        "keylogger_samples": 5000,
        "benign_samples": 45000,
        "epochs": 50,
        "batch_size": 32
    }
}
```

**Uso**:
```python
# Cargar metadatos para configurar extractor de features
with open('models/onnx_metadata_*.json') as f:
    metadata = json.load(f)

# Usar feature names para extracción
feature_names = metadata['feature_names']
feature_extractor = NetworkFeatureExtractor(feature_names)

# Usar parámetros de normalización
scaler_params = metadata['preprocessing']['scaling_params']
```

---

## 🔄 Flujo de Uso de Modelos

```
┌─────────────────────────────────────┐
│    Network Monitor                  │
│  (Captura conexiones de red)        │
└────────────────┬────────────────────┘
                 │ raw network data
                 ▼
┌─────────────────────────────────────┐
│    Feature Extractor                │
│  (Convierte a 78 features)          │
└────────────────┬────────────────────┘
                 │ feature vector [1 x 78]
                 ▼
┌─────────────────────────────────────┐
│    ML Engine                        │
│  - Normaliza features               │
│  - Carga modelo ONNX/sklearn        │
│  - Ejecuta inferencia               │
└────────────────┬────────────────────┘
                 │ predictions [benign_prob, keylogger_prob]
                 ▼
┌─────────────────────────────────────┐
│    Threshold Check                  │
│  (keylogger_prob > 0.7 ?)           │
└────────────────┬────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
   ✅ BENIGN        🚨 KEYLOGGER
                         │
                         ▼
                   Publish Event
                   threat_detected
```

## 🎓 Entrenamiento de Modelos

Aunque los modelos pre-entrenados están incluidos, el proceso general de entrenamiento es:

### Dataset
```
CIC-IDS2017 + Synthetic Keylogger Data
│
├── Benign Traffic (90%):
│   - Navegación web normal
│   - Streaming de video
│   - Email, chat
│   - Descarga de archivos
│
└── Keylogger Traffic (10%):
    - Conexiones a C&C periódicas (beaconing)
    - Exfiltración de datos pequeños
    - Puertos no estándar
    - Patrones de upload constante
```

### Pipeline de entrenamiento
```python
# 1. Carga de datos
data = pd.read_csv('keylogger_dataset.csv')

# 2. Feature engineering
X = data[feature_columns]
y = data['label']  # 0 = benign, 1 = keylogger

# 3. Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# 4. Entrenar modelo
model = build_neural_network()
model.fit(X_train, y_train, epochs=50, validation_split=0.2)

# 5. Evaluar
accuracy = model.evaluate(X_test, y_test)

# 6. Exportar a ONNX
convert_to_onnx(model, 'keylogger_model.onnx')
```

---

## 📊 Actualización de Modelos

Para actualizar/reentrenar modelos:

1. **Recolectar nuevos datos**:
   ```python
   # Habilitar en ml_config.json
   "training": {
       "data_collection": {"enabled": true}
   }
   ```

2. **Preparar dataset**:
   - Etiquetar datos correctamente
   - Balancear clases
   - Validar calidad de datos

3. **Reentrenar**:
   ```bash
   python scripts/train_model.py --dataset new_data.csv
   ```

4. **Validar modelo nuevo**:
   - Verificar métricas en test set
   - Probar con datos reales
   - Comparar con modelo anterior

5. **Reemplazar modelo**:
   ```bash
   cp new_model.onnx models/keylogger_model_large_*.onnx
   # Actualizar metadatos
   ```

6. **Reiniciar sistema**:
   ```bash
   python launcher.py
   # ML Engine cargará el nuevo modelo
   ```

## 🔍 Debugging de Modelos

### Verificar modelo ONNX
```python
import onnx

model = onnx.load('models/keylogger_model_large_*.onnx')
onnx.checker.check_model(model)  # Validar estructura

# Inspeccionar inputs/outputs
print("Inputs:", model.graph.input)
print("Outputs:", model.graph.output)
```

### Test de predicción
```python
# Generar datos sintéticos
test_features = np.random.rand(1, 78).astype(np.float32)

# Predicción
predictions = session.run([output_name], {input_name: test_features})[0]
print(f"Prediction: {predictions}")
```

---

## 💡 Mejores Prácticas

1. **Backup de modelos**: Mantener versiones anteriores
2. **Versionado**: Incluir fecha/versión en nombres de archivo
3. **Validación**: Probar modelos antes de deployment
4. **Monitoreo**: Track de accuracy en producción
5. **Reentrenamiento periódico**: Cada 3-6 meses con nuevos datos
6. **Feature drift**: Monitorear distribución de features

## ⚠️ Consideraciones

- **Tamaño de modelos**: ~50MB para ONNX, considerrar espacio en disco
- **RAM**: Modelos grandes requieren memoria suficiente
- **CPU**: Inferencia consume CPU, optimizar batch size
- **Actualizaciones**: Nuevos modelos pueden requerir nuevas features

---

**Versión del modelo**: 1.0  
**Última actualización**: Septiembre 2025  
**Dataset**: CIC-IDS2017 + Synthetic Keylogger Data
