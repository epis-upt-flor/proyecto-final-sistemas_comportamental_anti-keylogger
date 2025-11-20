# 🔍 Carpeta `/plugins/detectors` - Detectores de Amenazas

## Descripción General

La carpeta `plugins/detectors/` contiene los plugins especializados en **detección de amenazas** del Sistema Anti-Keylogger Unificado. Estos plugins implementan diferentes estrategias de análisis (Machine Learning, comportamiento heurístico, análisis de red, detección especializada) para identificar keyloggers y malware.

Cada detector es un **plugin independiente** que hereda de `BasePlugin` e implementa `DetectorInterface`, permitiendo su activación/desactivación dinámica y comunicación a través del Event Bus.

## 🎯 Filosofía de Detección Multi-Capa

El sistema implementa **defensa en profundidad** con múltiples detectores complementarios:

1. **ML Detector**: Análisis con modelos entrenados (alta precisión)
2. **Behavior Detector**: Heurística basada en reglas (rápido, flexible)
3. **Keylogger Detector**: Especializado en técnicas de keyloggers
4. **Network Detector**: Análisis de tráfico y conexiones sospechosas

Esta arquitectura multi-capa reduce falsos negativos y proporciona verificación cruzada de amenazas.

## 📁 Estructura de Detectores

```
plugins/detectors/
├── behavior_detector/      # Detección por comportamiento heurístico
│   ├── __init__.py
│   ├── plugin.py          # Plugin principal
│   ├── behavior_engine.py # Motor de análisis
│   ├── rule_engine.py     # Sistema de reglas
│   ├── whitelist_manager.py
│   └── config.json
│
├── keylogger_detector/    # Detector especializado de keyloggers
│   ├── __init__.py
│   ├── plugin.py
│   ├── keylogger_detector.py
│   ├── test_keylogger_detector.py
│   └── config.json
│
├── ml_detector/           # Detección con Machine Learning
│   ├── __init__.py
│   ├── plugin.py
│   ├── ml_engine.py       # Motor de ML
│   ├── feature_extractor.py
│   └── config.json
│
└── network_detector/      # Análisis de tráfico de red
    ├── __init__.py
    ├── plugin.py
    ├── network_analyzer.py
    ├── pattern_detector.py
    ├── ip_analyzer.py
    ├── threat_intelligence.py
    └── config.json
```

---

## 🤖 ML Detector - Detección con Machine Learning

### Descripción General

El **ML Detector** utiliza modelos de Machine Learning entrenados para identificar keyloggers basándose en características de comportamiento del sistema. Soporta modelos ONNX (inferencia rápida) y sklearn (fallback).

### Archivos Principales

#### `plugin.py`
**Propósito**: Plugin wrapper para el ML Detector

**Funcionalidad**:
- Hereda de `BasePlugin` e implementa `DetectorInterface`
- Inicializa el `MLEngine` con configuración
- Suscribe al Event Bus para recibir datos de monitores
- Publica eventos `threat_detected` cuando encuentra amenazas
- Gestiona ciclo de vida del detector

**Descripción Técnica**:
```python
class MLDetectorPlugin(BasePlugin, DetectorInterface):
    def initialize(self) -> bool:
        # Cargar configuración de ML
        # Inicializar MLEngine con modelo ONNX
        # Configurar umbrales de confianza
        
    def start(self) -> bool:
        # Suscribir a eventos de monitores
        # Iniciar análisis en tiempo real
        
    def detect_threats(self, data: Dict) -> List[Dict]:
        # Extraer características
        # Ejecutar predicción del modelo
        # Filtrar por confidence threshold
        # Retornar amenazas detectadas
```

**Eventos suscritos**:
- `network_data_collected`: Datos de red de monitores
- `process_data_collected`: Información de procesos
- `file_activity_detected`: Actividad de archivos

**Eventos publicados**:
- `threat_detected`: Cuando detecta amenaza con confianza suficiente

#### `ml_engine.py`
**Propósito**: Motor de Machine Learning con soporte ONNX y sklearn

**Funcionalidad**:
- Carga modelos ONNX con onnxruntime
- Fallback automático a modelos sklearn
- Gestión de metadata (clases, features)
- Preprocesamiento de datos
- Inferencia con timeout
- Caché de predicciones para rendimiento

**Descripción Técnica**:

**Clase Principal**: `MLEngine`

**Atributos**:
```python
onnx_model: InferenceSession        # Modelo ONNX Runtime
sklearn_model: Any                   # Modelo sklearn (backup)
label_classes: List[str]             # Clases de salida
feature_columns: List[str]           # Features esperadas
current_model_type: str              # 'ONNX' o 'sklearn'
prediction_cache: Dict               # Caché de predicciones
```

**Métodos clave**:

1. **`_initialize_engine()`**:
   - Carga label_classes.json
   - Carga metadata de features
   - Intenta cargar ONNX, fallback a sklearn
   - Valida modelo cargado

2. **`predict(features: np.ndarray) -> PredictionResult`**:
   - Valida dimensiones de features
   - Consulta caché si está habilitado
   - Ejecuta inferencia con timeout
   - Retorna resultado con probabilidades

3. **`predict_batch(features_batch: np.ndarray) -> List[PredictionResult]`**:
   - Predicción en lote para eficiencia
   - Procesa en chunks según batch_size
   - Manejo de errores individual

4. **`_preprocess_features(features: np.ndarray) -> np.ndarray`**:
   - Normalización (si configurado)
   - Manejo de valores faltantes
   - Escalado de features
   - Validación de tipos

**Características técnicas**:
- **Dual model support**: ONNX primario, sklearn backup
- **Performance**: Caché LRU de predicciones, batch processing
- **Robustez**: Timeout en inferencia, fallback automático
- **Observability**: Métricas detalladas (tiempo predicción, cache hits)

#### `feature_extractor.py`
**Propósito**: Extracción de características de datos brutos

**Funcionalidad**:
- Convierte datos de sistema en vectores de features
- Soporta múltiples fuentes (red, procesos, archivos)
- Features temporales y estadísticos
- Normalización y escalado

**Descripción Técnica**:

**Clase Principal**: `NetworkFeatureExtractor`

**Features extraídas** (basadas en dataset CIC-IDS2017):

**Características de Flujo**:
- `Flow Duration`: Duración total del flujo
- `Total Fwd/Bwd Packets`: Paquetes forward/backward
- `Flow Bytes/s`: Tasa de bytes por segundo
- `Flow Packets/s`: Tasa de paquetes por segundo

**Características de Paquetes**:
- `Packet Length Mean/Std/Max/Min`: Estadísticas de longitud
- `Fwd/Bwd Packet Length Stats`: Por dirección
- `Header Length`: Longitud de cabecera

**Características Temporales**:
- `Flow/Fwd/Bwd IAT Mean/Std`: Inter-Arrival Time
- `Active/Idle Mean/Std/Max/Min`: Tiempos activos e idle

**Características de Flags TCP**:
- `FIN/SYN/RST/PSH/ACK/URG Count`: Conteo de flags TCP
- `CWE/ECE Flag Count`: Flags de control de congestión

**Métodos clave**:

1. **`extract_features_from_network_data(network_data) -> np.ndarray`**:
   - Convierte lista de conexiones a DataFrame
   - Estrategia de extracción según datos disponibles
   - Calcula estadísticas por flujo
   - Retorna array 2D (flows × features)

2. **`_extract_flow_based_features(df) -> List[np.ndarray]`**:
   - Agrupa paquetes por flujo (src_ip, dst_ip, protocol)
   - Calcula estadísticas agregadas
   - Características temporales

3. **`_calculate_temporal_features(flow_packets) -> Dict`**:
   - Inter-arrival times
   - Períodos activos vs idle
   - Burst detection

**Consideraciones técnicas**:
- **Strategy Pattern**: Diferentes estrategias según datos disponibles
- **Performance**: Vectorización con NumPy, caching
- **Robustez**: Manejo de valores faltantes, outliers

---

## 🎭 Behavior Detector - Detección por Comportamiento

### Descripción General

El **Behavior Detector** usa análisis heurístico basado en reglas para identificar comportamientos sospechosos. No requiere modelos entrenados, operando con reglas configurables que detectan patrones conocidos de keyloggers y malware.

### Archivos Principales

#### `plugin.py`
**Propósito**: Plugin de detección por comportamiento

**Funcionalidad**:
- Coordina BehaviorEngine, RuleEngine y WhitelistManager
- Analiza datos de monitores contra reglas heurísticas
- Scoring agregado de múltiples reglas
- Whitelist para reducir falsos positivos

#### `behavior_engine.py`
**Propósito**: Motor principal de análisis heurístico

**Funcionalidad**:
- Coordina análisis de diferentes fuentes de datos
- Aplica filtrado por whitelist
- Análisis avanzado con correlación temporal
- Cache de análisis recientes
- Threading para análisis concurrente

**Descripción Técnica**:

**Clase Principal**: `BehaviorEngine`

**Componentes**:
```python
rule_engine: RuleEngine              # Motor de reglas
whitelist_manager: WhitelistManager  # Gestión de whitelist
behavior_timeline: Dict[deque]       # Timeline de comportamientos
analysis_cache: Dict                 # Caché de análisis
executor: ThreadPoolExecutor         # Análisis concurrente
```

**Métodos clave**:

1. **`analyze(monitor_name: str, data: List[Dict]) -> List[Dict]`**:
   Template Method para análisis completo:
   ```python
   # Paso 1: Filtrar por whitelist
   filtered_data = self._filter_whitelisted_data(data)
   
   # Paso 2: Análisis según tipo (Strategy Pattern)
   if monitor_name == 'process':
       threats = self._analyze_process_behavior(filtered_data)
   elif monitor_name == 'network':
       threats = self._analyze_network_behavior(filtered_data)
   
   # Paso 3: Análisis avanzado (correlación)
   if self.enable_advanced_analysis:
       threats = self._perform_advanced_analysis(threats, data)
   
   # Paso 4: Actualizar estadísticas
   self._update_stats(len(threats), analysis_time)
   ```

2. **`_analyze_process_behavior(data) -> List[Dict]`**:
   - Extrae características del proceso
   - Evalúa contra reglas de proceso
   - Scoring por CPU, memoria, APIs sospechosas
   - Detecta nombres sospechosos

3. **`_analyze_network_behavior(data) -> List[Dict]`**:
   - Analiza conexiones externas
   - Puertos sospechosos
   - Frecuencia de conexiones
   - Patrones de exfiltración

4. **`_perform_advanced_analysis(threats, data) -> List[Dict]`**:
   - Correlación temporal de eventos
   - Detección de campañas multi-etapa
   - Chain of compromise analysis
   - Ajuste de scoring por contexto

**Características técnicas**:
- **Multi-threaded**: ThreadPoolExecutor para análisis paralelo
- **Cached**: Resultados cacheados por TTL configurable
- **Timeline**: Correlación temporal con ventanas deslizantes
- **Adaptive**: Umbrales ajustables por configuración

#### `rule_engine.py`
**Propósito**: Motor de reglas heurísticas configurable

**Funcionalidad**:
- Sistema de reglas basado en patrones
- Diferentes tipos de reglas (proceso, red, archivo)
- Scoring con pesos configurables
- Chain of Responsibility para evaluación

**Descripción Técnica**:

**Clases principales**:

1. **`BaseRule` (Abstract)**:
   ```python
   class BaseRule(ABC):
       rule_id: str
       name: str
       risk_weight: float        # 0.0 - 1.0
       rule_type: RuleType       # PROCESS, NETWORK, FILE, SYSTEM
       
       @abstractmethod
       def evaluate(data: Dict) -> Tuple[bool, float, Dict]:
           """Retorna (matched, risk_score, details)"""
   ```

2. **Reglas concretas**:

   **`ProcessNameRule`**: Patrones de nombres sospechosos
   ```python
   patterns = [r'keylog', r'hook', r'capture', r'spy']
   # Evalúa nombres de proceso contra regex
   ```

   **`HighCPURule`**: Uso anormal de CPU
   ```python
   threshold = 80  # % CPU
   # Detecta procesos con alto uso sostenido
   ```

   **`SuspiciousAPIRule`**: APIs de Windows peligrosas
   ```python
   apis = ['SetWindowsHookEx', 'GetAsyncKeyState', 'BitBlt']
   # Detecta uso de APIs típicas de keyloggers
   ```

   **`NetworkFrequencyRule`**: Conexiones anómalas
   ```python
   max_connections = 10  # por minuto
   # Beaconing detection
   ```

   **`FilePatternRule`**: Archivos de log sospechosos
   ```python
   patterns = [r'.*keylog.*\.txt$', r'.*password.*\.txt$']
   # Detecta archivos típicos de keyloggers
   ```

**RuleEngine**:
```python
class RuleEngine:
    rules: Dict[RuleType, List[BaseRule]]
    
    def evaluate_all_rules(data: Dict, rule_type: RuleType) -> List[Dict]:
        # Chain of Responsibility: Evalúa todas las reglas
        # Agrega scores de reglas matched
        # Retorna amenazas con score >= threshold
```

**Características técnicas**:
- **Extensible**: Fácil añadir nuevas reglas
- **Configurable**: Reglas y pesos en config.json
- **Composable**: Reglas se combinan para scoring final
- **Observable**: Estadísticas por regla

#### `whitelist_manager.py`
**Propósito**: Gestión de lista blanca de procesos seguros

**Funcionalidad**:
- Carga whitelist desde config
- Verificación rápida de procesos
- Excepciones configurables
- Reduce falsos positivos

**Descripción Técnica**:

**Clase Principal**: `WhitelistManager`

```python
class WhitelistManager:
    enabled: bool
    allowed_processes: Set[str]
    trusted_directories: List[Path]
    monitoring_exceptions: Dict
    
    def is_whitelisted(process_name: str, process_path: str) -> bool:
        # Verifica proceso contra whitelist
        # Considera nombre, ruta y excepciones
```

**Estrategias de whitelisting**:
1. **Por nombre**: Proceso en allowed_processes
2. **Por directorio**: Path en trusted_directories
3. **Por excepción**: Proceso en monitoring_exceptions

---

## 🎯 Keylogger Detector - Detector Especializado

### Descripción General

El **Keylogger Detector** es un plugin **altamente especializado** en detectar keyloggers específicamente. Basado en análisis de keyloggers reales (Harem.c, Ghost_Writer.cs, EncryptedKeylogger.py), implementa detección de técnicas concretas.

### Archivo Principal

#### `keylogger_detector.py`
**Propósito**: Detector especializado en keyloggers

**Funcionalidad**:
- Detecta hooks de teclado (SetWindowsHookEx)
- Identifica APIs de captura de pantalla
- Analiza patrones de archivos de log
- Detecta comportamiento stealth
- Inspección de memoria en busca de hooks

**Descripción Técnica**:

**Clase Principal**: `KeyloggerDetector`

**Patrones de detección**:

1. **APIs Sospechosas de Windows**:
   ```python
   HOOK_APIS = [
       'SetWindowsHookEx',      # Principal para hooks
       'GetAsyncKeyState',      # Estado de teclas
       'BitBlt',                # Captura de pantalla
       'CreateCompatibleDC',    # Contexto para captura
   ]
   ```

2. **Patrones de Archivos de Log**:
   ```python
   LOG_PATTERNS = [
       r'.*key.*log.*\.txt$',     # keylog.txt
       r'.*readme\.txt$',          # Harem.c
       r'.*text.*data.*\.txt$',    # Ghost_Writer
       r'.*clipboard.*\.txt$',
       r'.*screenshot.*\.(png|jpg)$'
   ]
   ```

3. **Comportamientos Stealth**:
   - Procesos ocultos (sin ventana visible)
   - Autostart registry keys
   - Process injection
   - Anti-debugging techniques

**Métodos clave**:

1. **`analyze_process_for_keylogger(process) -> Dict`**:
   ```python
   # Verifica APIs cargadas en memoria
   # Detecta hooks instalados
   # Analiza conexiones de red
   # Busca archivos de log asociados
   # Score agregado de múltiples indicadores
   ```

2. **`check_keyboard_hooks(process) -> bool`**:
   ```python
   # Usa pywin32 para inspeccionar hooks
   # Verifica WH_KEYBOARD_LL hooks
   # Identifica proceso que instaló el hook
   ```

3. **`scan_for_log_files(process_path) -> List[str]`**:
   ```python
   # Busca archivos con patrones sospechosos
   # En directorio del proceso y subdirectorios
   # Analiza contenido si es texto
   ```

4. **`detect_screen_capture_activity(process) -> bool`**:
   ```python
   # Detecta APIs de BitBlt, GetDC
   # Frecuencia de capturas
   # Archivos de imagen generados
   ```

**Scoring de amenaza**:
```python
score = 0.0
if has_keyboard_hooks: score += 0.4
if has_screen_capture: score += 0.3
if has_log_files: score += 0.2
if has_network_exfiltration: score += 0.3
if is_hidden_process: score += 0.2

if score >= 0.7: risk_level = "CRITICAL"
```

**Características técnicas**:
- **Signature-based**: Patrones de keyloggers conocidos
- **Behavior-based**: Detecta técnicas genéricas
- **Memory inspection**: Hooks en memoria
- **File system analysis**: Archivos de log

---

## 🌐 Network Detector - Análisis de Tráfico

### Descripción General

El **Network Detector** monitorea y analiza tráfico de red para detectar exfiltración de datos, conexiones a C&C (Command & Control), y patrones de red anómalos típicos de keyloggers y malware.

### Archivos Principales

#### `plugin.py`
**Propósito**: Plugin de detección de red

**Funcionalidad**:
- Coordina NetworkAnalyzer, PatternDetector, IPAnalyzer
- Analiza conexiones activas del sistema
- Detecta patrones de beaconing
- Correlaciona con threat intelligence

#### `network_analyzer.py`
**Propósito**: Análisis detallado de conexiones

**Funcionalidad**:
- Captura conexiones activas con psutil
- Estadísticas por conexión (bytes, packets, duración)
- Detección de anomalías de tráfico
- Baseline de comportamiento normal

**Descripción Técnica**:

**Clase Principal**: `NetworkAnalyzer`

**Métricas capturadas**:
```python
@dataclass
class NetworkStats:
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    first_seen: datetime
    last_seen: datetime
    connection_count: int
    
    @property
    def upload_ratio(self) -> float:
        # Ratio de upload vs download
        # Alto upload puede indicar exfiltración
```

**Métodos clave**:

1. **`get_active_connections() -> List[Dict]`**:
   ```python
   # Captura conexiones con psutil
   # Enriquece con datos de proceso
   # Calcula estadísticas en tiempo real
   # Filtra conexiones internas
   ```

2. **`analyze_connection_patterns(connections) -> List[Dict]`**:
   ```python
   # Detecta beaconing (conexiones periódicas)
   # Identifica data exfiltration patterns
   # Analiza frecuencia de conexiones
   # Score por anomalía
   ```

3. **`establish_network_baseline() -> Dict`**:
   ```python
   # Captura estado inicial de red
   # Puertos comunes
   # Procesos con red normal
   # Para detección de desviaciones
   ```

#### `pattern_detector.py`
**Propósito**: Detección de patrones maliciosos de red

**Funcionalidad**:
- Beaconing detection (C&C communications)
- Data exfiltration patterns
- Port scanning detection
- DGA (Domain Generation Algorithm) detection

**Descripción Técnica**:

**Patrones detectados**:

1. **Beaconing**:
   ```python
   # Conexiones periódicas regulares
   # Típico de malware contactando C&C
   if connections_per_minute > 5 and interval_stddev < 2:
       return "BEACONING_DETECTED"
   ```

2. **Data Exfiltration**:
   ```python
   # Alto upload rate sostenido
   # Especialmente a IPs externas
   if upload_ratio > 0.8 and bytes_sent > threshold:
       return "EXFILTRATION_SUSPECTED"
   ```

3. **Port Scanning**:
   ```python
   # Múltiples conexiones a diferentes puertos
   # En corto período de tiempo
   if unique_ports > 20 and time_window < 60:
       return "PORT_SCAN_DETECTED"
   ```

#### `ip_analyzer.py`
**Propósito**: Análisis de reputación de IPs

**Funcionalidad**:
- Verificación contra listas de IPs maliciosas
- Geolocalización de IPs
- Scoring de reputación
- Integración con threat intelligence

#### `threat_intelligence.py`
**Propósito**: Integración con fuentes de inteligencia de amenazas

**Funcionalidad**:
- Carga listas de IPs/dominios maliciosos
- Actualización periódica desde fuentes
- Caché local de threat intel
- API para consultas rápidas

**Descripción Técnica**:

**Fuentes de threat intel**:
- `threat_intel/malicious_ips.txt`: IPs conocidas maliciosas
- `threat_intel/domains.txt`: Dominios sospechosos
- APIs externas (opcional): AbuseIPDB, VirusTotal

---

## 🔄 Flujo de Detección Multi-Capa

```
┌───────────────────────────────────────────────────────┐
│         Monitores capturan datos del sistema         │
│    (Process Monitor, File Monitor, Network Monitor)  │
└─────────────────────┬─────────────────────────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │      Event Bus          │
          │  (data_collected events)│
          └───────────┬─────────────┘
                      │
       ┌──────────────┼──────────────┬─────────────┐
       │              │               │             │
       ▼              ▼               ▼             ▼
┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐
│    ML    │  │   Behavior   │  │ Keylogger│  │ Network  │
│ Detector │  │   Detector   │  │ Detector │  │ Detector │
└────┬─────┘  └──────┬───────┘  └────┬─────┘  └────┬─────┘
     │               │               │              │
     └───────────────┴───────────────┴──────────────┘
                     │
        ┌────────────┴────────────┐
        │  Threat Aggregation     │
        │  (Correlación cruzada)  │
        └────────────┬────────────┘
                     │
                     ▼
            ┌────────────────┐
            │ Event Bus      │
            │threat_detected │
            └────────┬───────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
  ┌─────────┐             ┌─────────────┐
  │ Alert   │             │ Quarantine  │
  │ Manager │             │  Handler    │
  └─────────┘             └─────────────┘
```

## 📊 Comparación de Detectores

| Característica       | ML Detector | Behavior Detector | Keylogger Detector | Network Detector |
|---------------------|-------------|-------------------|-------------------|------------------|
| **Precisión**       | ⭐⭐⭐⭐⭐     | ⭐⭐⭐⭐             | ⭐⭐⭐⭐⭐            | ⭐⭐⭐⭐           |
| **Velocidad**       | ⭐⭐⭐        | ⭐⭐⭐⭐⭐            | ⭐⭐⭐              | ⭐⭐⭐⭐           |
| **Falsos Positivos**| Bajo        | Medio             | Muy Bajo          | Medio            |
| **Cobertura**       | Amplia      | Amplia            | Keyloggers        | Red/Exfiltración |
| **Recursos**        | Alto        | Medio             | Medio             | Bajo             |
| **Actualizaciones** | Reentrenar  | Modificar reglas  | Agregar firmas    | Actualizar IPs   |

## ⚙️ Configuración de Detectores

Cada detector tiene su `config.json`:

```json
{
    "enabled": true,
    "sensitivity": "high",     // low, medium, high, paranoid
    "confidence_threshold": 0.7,
    "max_threats_per_scan": 100,
    "analysis_timeout_ms": 5000,
    "publish_all_detections": false,  // o solo high-confidence
    "advanced_analysis": {
        "enabled": true,
        "correlation_window_minutes": 10
    }
}
```

## 🧪 Testing de Detectores

```python
# Test ML Detector
from plugins.detectors.ml_detector.plugin import MLDetectorPlugin

plugin = MLDetectorPlugin(config)
plugin.initialize()
plugin.start()

# Simular datos de red
test_data = {...}
threats = plugin.detect_threats(test_data)
assert len(threats) > 0

# Test Behavior Detector
from plugins.detectors.behavior_detector.plugin import BehaviorDetectorPlugin

plugin = BehaviorDetectorPlugin(config)
threats = plugin.analyze_process_behavior(suspicious_process_data)
```

## 💡 Mejores Prácticas

1. **Habilitar múltiples detectores**: Defensa en profundidad
2. **Ajustar umbrales gradualmente**: Empezar alto, reducir según necesidad
3. **Mantener whitelist actualizada**: Reducir falsos positivos
4. **Actualizar threat intelligence**: IPs y dominios maliciosos
5. **Monitorear métricas**: False positive rate, detection rate
6. **Reentrenar modelos ML**: Con nuevos datos periódicamente

## 🔐 Consideraciones de Seguridad

- **Evasion techniques**: Malware puede detectar el antivirus y modificar comportamiento
- **Privilege escalation**: Algunos detectores requieren permisos elevados
- **Performance impact**: Balancear detección vs recursos del sistema
- **False positives**: Validar detecciones antes de acciones drásticas

## 🔗 **Enlaces a Detectores Específicos**

### Detectores Principales
- **[🎯 Behavior Detector](behavior_detector/README.md)** - Detección heurística de comportamiento
- **[⌨️ Keylogger Detector](keylogger_detector/README.md)** - Detector especializado de keyloggers  
- **[🤖 ML Detector](ml_detector/README.md)** - Detección con machine learning
- **[🌐 Network Detector](network_detector/README.md)** - Análisis de tráfico de red
- **[🛡️ IAST Detector](iast_detector/README.md)** - Auto-protección y detección IAST
- **[🤖 Detectores Generados](generated/README.md)** - Detectores auto-generados

### Enlaces Relacionados
- **[📋 README Principal](../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../README.md)** - Arquitectura de plugins
- **[🧠 Recursos Compartidos](../shared/README.md)** - Motor de inteligencia unificado
- **[📊 Monitores](../monitors/README.md)** - Sistema de monitoreo
- **[🚨 Handlers](../handlers/README.md)** - Gestores de respuesta
- **[⚙️ Configuración](../../config/README.md)** - Sistema de configuración
- **[🤖 Modelos ML](../../models/README.md)** - Modelos y metadatos
- **[📊 Core Engine](../../core/README.md)** - Motor principal del sistema

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../README.md) - Sistema de Detección Multi-Capa Profesional**

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
