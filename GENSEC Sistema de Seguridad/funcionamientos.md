# 🔧 Funcionamiento Interno del Sistema Antivirus Unificado

## 📋 Tabla de Contenidos

1. [🏗️ Arquitectura General](#arquitectura-general)
2. [🎯 Motor Principal (Engine)](#motor-principal-engine)
3. [🔌 Sistema de Plugins](#sistema-de-plugins)
4. [🕵️ Detectores de Amenazas](#detectores-de-amenazas)
5. [📊 Monitores del Sistema](#monitores-del-sistema)
6. [🔄 Event Bus y Comunicación](#event-bus-y-comunicacion)
7. [🧪 Integration Engine (TDD/IAST/MDSD)](#integration-engine-tddiastmdsd)
8. [📈 Flujo de Datos Completo](#flujo-de-datos-completo)
9. [🎨 Interfaces y Patrones](#interfaces-y-patrones)

---

## 🏗️ Arquitectura General

### Patrón Facade - Motor Principal

El sistema utiliza **Facade Pattern** con `UnifiedAntivirusEngine` como punto de entrada único:

```python
# core/engine.py - Líneas 31-45
class UnifiedAntivirusEngine:
    """
    Motor principal del Sistema Anti-Keylogger Unificado.
    
    Implementa Facade Pattern que simplifica:
    - Gestión de plugins
    - Comunicación entre componentes  
    - Ciclo de vida del sistema
    - Configuración global
    
    Es el punto de entrada principal del sistema.
    """
    
    def __init__(self, config_path: str = "config/unified_config.toml"):
        self.config_path = config_path
        self.plugin_manager = PluginManager(self)
        self.plugin_registry = PluginRegistry()
        self.is_running = False
```

### Componentes Principales

1. **UnifiedAntivirusEngine** - Facade principal
2. **PluginManager** - Factory para plugins
3. **PluginRegistry** - Registry centralizado
4. **EventBus** - Observer pattern para comunicación
5. **Detectores** - Strategy pattern para diferentes algoritmos
6. **Monitores** - Strategy pattern para diferentes fuentes de datos

---

## 🎯 Motor Principal (Engine)

### Clase: `UnifiedAntivirusEngine`
**Archivo**: `core/engine.py`

#### Responsabilidades Clave:

1. **Inicialización del Sistema**:
```python
def initialize(self, mode: str = "FULL") -> bool:
    """Inicializa el sistema completo"""
    # 1. Cargar configuración
    # 2. Inicializar PluginManager  
    # 3. Descubrir y cargar plugins
    # 4. Configurar Event Bus
    # 5. Suscribirse a eventos críticos
```

2. **Gestión del Ciclo de Vida**:
```python
def start(self) -> bool:
    """Inicia el sistema antivirus"""
    # 1. Activar plugins por categorías
    # 2. Iniciar monitores
    # 3. Configurar detectores
    # 4. Establecer comunicación Event Bus

def shutdown(self):
    """Cierre limpio del sistema"""
    # 1. Desactivar plugins activos
    # 2. Limpiar recursos
    # 3. Cerrar conexiones
```

3. **Coordinación de Componentes**:
   - Maneja comunicación entre plugins
   - Distribuye eventos del sistema
   - Consolida resultados de detección
   - Gestiona alertas y respuestas

---

## 🔌 Sistema de Plugins

### Patrón Factory - PluginManager

#### Clase: `PluginManager`
**Archivo**: `core/plugin_manager.py`

**Funciones Principales**:

1. **Descubrimiento Automático**:
```python
def scan_plugins(self) -> Dict[str, Any]:
    """Escanea directorio plugins/ automáticamente"""
    # 1. Recorre estructura de carpetas
    # 2. Identifica plugins por plugin.py
    # 3. Extrae metadata y configuración
    # 4. Valida interfaces implementadas
```

2. **Carga Dinámica**:
```python
def load_plugin(self, plugin_info: Dict) -> Optional[Any]:
    """Carga plugin dinámicamente"""
    # 1. Importa módulo Python
    # 2. Instancia clase plugin
    # 3. Valida interfaces requeridas
    # 4. Registra en PluginRegistry
```

### Patrón Registry - PluginRegistry

#### Clase: `PluginRegistry`  
**Archivo**: `core/plugin_registry.py`

**Funciones de Registro**:
```python
def register_plugin(self, plugin_name: str, plugin_class: Any, 
                   category: str, metadata: Dict = None):
    """Registra plugin en categoría específica"""
    
def get_plugins_by_category(self, category: str) -> Dict[str, Any]:
    """Obtiene plugins por categoría (detectors, monitors, handlers)"""
```

---

## 🕵️ Detectores de Amenazas

Los detectores implementan **Strategy Pattern** para intercambiar algoritmos de detección.

### Interface Base: `DetectorInterface`
**Archivo**: `core/interfaces.py` (Líneas 14-56)

```python
class DetectorInterface(ABC):
    """Interface para plugins detectores usando Strategy Pattern"""

    @abstractmethod
    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detecta amenazas en los datos proporcionados"""
    
    @abstractmethod  
    def get_confidence_score(self) -> float:
        """Retorna el nivel de confianza de la última detección"""
        
    @abstractmethod
    def update_signatures(self) -> bool:
        """Actualiza las firmas/patrones de detección"""
        
    @abstractmethod
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Estadísticas de detección del plugin"""
```

### 1. Behavior Detector Plugin

#### Clase: `BehaviorDetectorPlugin`
**Archivo**: `plugins/detectors/behavior_detector/plugin.py`

**Proceso de Detección**:

1. **Análisis Heurístico**:
```python
class BehaviorDetectorPlugin(BasePlugin, DetectorInterface):
    def __init__(self):
        # Motor de comportamiento
        self.behavior_engine = BehaviorEngine(self.config)
        
        # Motor de reglas
        self.rule_engine = RuleEngine() 
        
        # Gestor de whitelist
        self.whitelist_manager = WhitelistManager()
```

2. **Detección en Tiempo Real**:
```python
def _process_system_events(self):
    """Procesa eventos del sistema en background"""
    while self.is_running:
        # 1. Obtener procesos activos
        # 2. Analizar comportamiento con BehaviorEngine  
        # 3. Aplicar reglas con RuleEngine
        # 4. Verificar whitelist
        # 5. Generar alertas si es necesario
```

3. **Motor de Comportamiento**:
```python
# behavior_detector/behavior_engine.py
class BehaviorEngine:
    def analyze_process_behavior(self, process_info: Dict) -> float:
        """Analiza comportamiento de proceso y retorna score de riesgo"""
        # 1. Análisis de memoria
        # 2. Análisis de archivos abiertos
        # 3. Análisis de conexiones de red
        # 4. Cálculo de score de suspición
```

### 2. Keylogger Detector Plugin

#### Clase: `KeyloggerDetectorPlugin`  
**Archivo**: `plugins/detectors/keylogger_detector/plugin.py`

**Especialización en Keyloggers**:

1. **Patrones Específicos** (Líneas 60-120):
```python
class KeyloggerDetector(BasePlugin):
    # Patrones de archivos de keylogger basados en análisis real
    self.log_file_patterns = [
        r".*key.*log.*\.txt$",      # key_log.txt, keylog.txt
        r".*readme\.txt$",          # Harem.c usa readme.txt  
        r".*text.*data.*\.txt$",    # Ghost_Writer usa Text_Data.txt
        r".*screenshot.*\.(png|jpg)$",  # screenshot files
        r".*pass.*word.*\.txt$",    # password logs
        # ... más patrones
    ]
```

2. **APIs Sospechosas de Windows** (Líneas 130-180):
```python
    # APIs principales para keyloggers
    self.suspicious_apis = [
        "SetWindowsHookEx",     # Principal API para hooks
        "CallNextHookEx",       # Continuación del hook
        "GetAsyncKeyState",     # Estado de teclas async
        "BitBlt",              # Captura de pantalla - CRÍTICO
        "CreateCompatibleDC",   # Para captura - CRÍTICO
        # ... más APIs
    ]
```

3. **Proceso de Análisis**:
```python
def analyze_process_for_keylogger(self, pid: int) -> Dict[str, Any]:
    """Análisis especializado para detectar keyloggers"""
    # 1. Verificar APIs cargadas (SetWindowsHookEx, etc.)
    # 2. Analizar archivos de log sospechosos
    # 3. Detectar comportamiento stealth
    # 4. Verificar patrones de captura de pantalla
    # 5. Calcular score de confianza específico
```

### 3. ML Detector Plugin

#### Clase: `MLDetectorPlugin`
**Archivo**: `plugins/detectors/ml_detector/plugin.py`

**Motor de Machine Learning**:

1. **MLEngine** (`ml_detector/ml_engine.py` - Líneas 50-100):
```python
class MLEngine:
    """Motor de Machine Learning con soporte para ONNX y sklearn"""
    
    def __init__(self, config: Dict[str, Any]):
        # Modelos soportados
        self.onnx_model = None          # Modelo ONNX optimizado
        self.sklearn_model = None       # Fallback sklearn
        self.label_classes = []         # ['Benign', 'Keylogger']
        self.feature_columns = []       # 81 características
```

2. **Predicción con Fallback**:
```python
def predict(self, features: np.ndarray) -> PredictionResult:
    """Predicción con fallback automático"""
    try:
        # 1. Intentar predicción ONNX (más rápida)
        if self.onnx_model:
            return self._predict_onnx(features)
        # 2. Fallback a sklearn si ONNX falla
        elif self.sklearn_model:
            return self._predict_sklearn(features)
    except Exception as e:
        # 3. Log error y retornar resultado seguro
        logger.error(f"ML prediction failed: {e}")
```

3. **Feature Extraction**:
```python
# ml_detector/feature_extractor.py  
class NetworkFeatureExtractor:
    """Extrae 81 características de procesos para ML"""
    def extract_features(self, process_info: Dict) -> np.ndarray:
        # 1. Características de proceso (CPU, memoria, archivos)
        # 2. Características de red (conexiones, puertos)
        # 3. Características de comportamiento (APIs, hooks)
        # 4. Normalización y formato para modelo
```

### 4. Network Detector Plugin

#### Clase: `NetworkDetectorPlugin`
**Archivo**: `plugins/detectors/network_detector/plugin.py`

**Análisis de Tráfico de Red**:

1. **Detección de Patrones Maliciosos**:
```python
def analyze_network_connections(self, process_pid: int) -> List[Dict]:
    """Analiza conexiones de red de un proceso"""
    # 1. Obtener conexiones activas del proceso
    # 2. Verificar IPs contra threat intelligence
    # 3. Analizar patrones de tráfico sospechosos
    # 4. Detectar comunicación C&C (Command & Control)
```

2. **Threat Intelligence**:
```python
# network_detector/threat_intelligence.py
class ThreatIntelligence:
    def is_malicious_ip(self, ip: str) -> bool:
        """Verifica IP contra base de datos de amenazas"""
        # 1. Consultar threat_intel/malicious_ips.txt
        # 2. Verificar rangos de IPs conocidas maliciosas
        # 3. Análisis de geolocalización sospechosa
```

---

## 🧪 Integration Engine (TDD/IAST/MDSD)

### Clase: `IntegrationEnginePlugin`
**Archivo**: `plugins/detectors/integration_engine/plugin.py`

**Arquitectura de Workers Concurrentes**:

1. **TDD Worker** (Líneas 200-250):
```python
def _tdd_worker(self):
    """Worker de Test-Driven Development"""
    tdd_logger = self._setup_logger('tdd_integration', 'logs/tdd_integration.log')
    
    while not self.stop_event.wait(self.tdd_config['test_interval']):
        # 1. Ejecutar suite de tests con pytest
        # 2. Verificar tests/tdd_01_api_hooking_detection
        # 3. Verificar tests/tdd_02_port_detection  
        # 4. Log resultados individuales
        # 5. Mantener estadísticas de cobertura
```

2. **IAST Worker** (Líneas 280-330):
```python  
def _iast_worker(self):
    """Worker de Interactive Application Security Testing"""
    iast_logger = self._setup_logger('iast_security', 'logs/iast_security.log')
    
    while not self.stop_event.wait(self.iast_config['scan_interval']):
        # 1. Ejecutar análisis de vulnerabilidades
        # 2. Detectar SQL Injection, XSS
        # 3. Análizar seguridad de APIs  
        # 4. Generar reportes de seguridad
        # 5. Log hallazgos de vulnerabilidades
```

3. **MDSD Worker** (Líneas 350-400):
```python
def _mdsd_worker(self):
    """Worker de Model-Driven Software Development"""  
    mdsd_logger = self._setup_logger('mdsd_generator', 'logs/mdsd_generator.log')
    
    while not self.stop_event.wait(self.mdsd_config['generation_interval']):
        # 1. Generar templates de detectores
        # 2. Crear código para Ransomware Detector
        # 3. Crear código para Trojan Detector
        # 4. Workflow Engine para automatización
        # 5. Log progreso de generación
```

**Coordinación de Threads**:
```python  
def start(self) -> bool:
    """Inicia todos los workers de integración"""
    # 1. TDD Thread cada 60 segundos
    self.tdd_thread = threading.Thread(target=self._tdd_worker, daemon=True)
    
    # 2. IAST Thread cada 45 segundos  
    self.iast_thread = threading.Thread(target=self._iast_worker, daemon=True)
    
    # 3. MDSD Thread cada 120 segundos
    self.mdsd_thread = threading.Thread(target=self._mdsd_worker, daemon=True)
    
    # Iniciar todos los workers concurrentemente
    for thread in [self.tdd_thread, self.iast_thread, self.mdsd_thread]:
        thread.start()
```

---

## 📊 Monitores del Sistema

### Interface Base: `MonitorInterface`
**Archivo**: `core/interfaces.py` (Líneas 65-95)

```python
class MonitorInterface(ABC):
    """Interface para plugins monitores usando Strategy Pattern"""
    
    @abstractmethod
    def start_monitoring(self) -> bool:
        """Inicia el monitoreo continuo del sistema"""
        
    @abstractmethod  
    def get_current_data(self) -> Dict[str, Any]:
        """Obtiene datos actuales del sistema que está monitoreando"""
        
    @abstractmethod
    def set_event_callback(self, callback: Callable) -> bool:
        """Configura callback para eventos detectados"""
```

### Tipos de Monitores

1. **Process Monitor**: Monitorea creación/terminación de procesos
2. **File Monitor**: Vigila acceso y modificación de archivos  
3. **Network Monitor**: Supervisa conexiones de red
4. **Registry Monitor**: Observa cambios en registro de Windows

**Flujo de Monitoreo**:
```python
# Patrón Observer implementado en monitores
class ProcessMonitor(BasePlugin, MonitorInterface):
    def start_monitoring(self):
        """Inicia monitoreo de procesos"""
        while self.is_monitoring:
            # 1. Detectar nuevos procesos
            new_processes = self._scan_new_processes()
            
            # 2. Por cada proceso nuevo, publicar evento
            for process in new_processes:
                event = Event(
                    event_type="process_created",
                    source="process_monitor", 
                    data=process
                )
                event_bus.publish(event)  # Notificar a detectores
```

---

## 🔄 Event Bus y Comunicación

### Patrón Observer - EventBus

#### Clase: `EventBus`
**Archivo**: `core/event_bus.py`

**Comunicación Desacoplada**:

1. **Publicación de Eventos**:
```python
class EventBus:
    def publish(self, event: Event) -> None:
        """Publica evento a todos los suscriptores"""
        # 1. Obtener suscriptores para el tipo de evento
        subscribers = self.subscriptions.get(event.event_type, [])
        
        # 2. Notificar a cada suscriptor asíncronamente
        for subscriber_id, callback in subscribers:
            try:
                callback(event)  # Llamar callback del plugin
            except Exception as e:
                logger.error(f"Error notifying subscriber {subscriber_id}: {e}")
```

2. **Suscripción de Plugins**:
```python  
def subscribe(self, event_type: str, subscriber_id: str, 
              callback: Callable[[Event], None]) -> bool:
    """Suscribe plugin a tipo de evento específico"""
    # Plugins se suscriben a eventos de su interés
    # Ej: keylogger_detector se suscribe a 'process_created'
```

**Tipos de Eventos del Sistema**:
- `process_created` - Nuevo proceso detectado
- `file_created` - Nuevo archivo creado
- `network_connection` - Nueva conexión de red
- `api_call_detected` - API sospechosa detectada
- `threat_detected` - Amenaza identificada
- `plugin_error` - Error en plugin
- `system_shutdown` - Cierre del sistema

---

## 📈 Flujo de Datos Completo

### 1. Inicialización del Sistema

```
[production_launcher.py]
         ↓
[UnifiedAntivirusEngine.initialize()]
         ↓
[PluginManager.scan_plugins()] → Descubre 8 plugins
         ↓  
[PluginRegistry.register_plugins()] → Registra por categorías
         ↓
[EventBus.initialize()] → Configura comunicación  
         ↓
[Engine.start()] → Activa plugins por categorías
```

### 2. Flujo de Detección en Tiempo Real

```
[ProcessMonitor] → Detecta nuevo proceso 'ejemplo.exe'
         ↓
[EventBus.publish('process_created')] → Notifica evento
         ↓
[Detectores Suscritos Reciben Evento]:
    • BehaviorDetector → Análisis heurístico
    • KeyloggerDetector → Verificar APIs/patrones  
    • MLDetector → Predicción con modelo ONNX
    • NetworkDetector → Analizar conexiones
         ↓
[Cada Detector Procesa en Paralelo]:
    • BehaviorDetector: Score = 0.3 (bajo riesgo)
    • KeyloggerDetector: Score = 0.8 (¡AMENAZA!)  
    • MLDetector: Score = 0.9 (¡KEYLOGGER!)
    • NetworkDetector: Score = 0.1 (normal)
         ↓
[EventBus.publish('threat_detected')] → Si score > threshold
         ↓
[Handlers Processan Amenaza]:
    • AlertManager → Genera alerta visual
    • LoggerHandler → Escribe a logs individuales  
    • QuarantineHandler → Aísla archivo si necesario
```

### 3. Logging Individual por Plugin

```
[Cada Plugin Mantiene Su Propio Logger]:

BehaviorDetector → logs/behavior_detector.log
KeyloggerDetector → logs/keylogger_detector.log  
MLDetector → logs/ml_detector.log
NetworkDetector → logs/network_detector.log
IntegrationEngine → logs/integration_engine.log
TDD Worker → logs/tdd_integration.log
IAST Worker → logs/iast_security.log  
MDSD Worker → logs/mdsd_generator.log
Frontend → logs/frontend.log
Sistema → logs/antivirus.log
```

### 4. Integration Engine en Paralelo

```
[IntegrationEngine inicia 3 workers concurrentes]:

TDD Worker (cada 60s):
    └─ Ejecuta pytest tests/tdd_01_api_hooking_detection
    └─ Ejecuta pytest tests/tdd_02_port_detection  
    └─ Logs resultados → logs/tdd_integration.log

IAST Worker (cada 45s):  
    └─ Análisis SQL Injection
    └─ Análisis XSS
    └─ Tests de penetración
    └─ Logs hallazgos → logs/iast_security.log

MDSD Worker (cada 120s):
    └─ Genera Ransomware Detector template
    └─ Genera Trojan Detector template
    └─ Workflow Engine automation
    └─ Logs progreso → logs/mdsd_generator.log
```

---

## 🎨 Interfaces y Patrones

### Patrones de Diseño Implementados

1. **Facade Pattern**:
   - `UnifiedAntivirusEngine` - Interfaz simplificada
   - Oculta complejidad del sistema de plugins

2. **Observer Pattern**:
   - `EventBus` - Comunicación desacoplada  
   - Plugins se suscriben a eventos de interés

3. **Strategy Pattern**:
   - `DetectorInterface` - Algoritmos intercambiables
   - `MonitorInterface` - Fuentes de datos intercambiables

4. **Factory Pattern**:
   - `PluginManager` - Creación dinámica de plugins
   - Carga automática desde directorios

5. **Registry Pattern**:
   - `PluginRegistry` - Registro centralizado
   - Gestión de metadatos de plugins

6. **Template Method**:
   - `BasePlugin` - Ciclo de vida común
   - Métodos abstractos para especialización

### Interfaces Clave

#### DetectorInterface (Strategy)
```python
# Cada detector implementa esta interfaz
class BehaviorDetectorPlugin(BasePlugin, DetectorInterface):
    def detect_threats(self, data) -> List[Dict]: 
        # Algoritmo específico de comportamiento
        
class KeyloggerDetectorPlugin(BasePlugin, DetectorInterface):  
    def detect_threats(self, data) -> List[Dict]:
        # Algoritmo específico de keyloggers
        
class MLDetectorPlugin(BasePlugin, DetectorInterface):
    def detect_threats(self, data) -> List[Dict]:
        # Algoritmo de Machine Learning
```

#### MonitorInterface (Strategy)  
```python  
# Cada monitor implementa esta interfaz
class ProcessMonitor(BasePlugin, MonitorInterface):
    def start_monitoring(self) -> bool:
        # Monitoreo específico de procesos
        
class FileMonitor(BasePlugin, MonitorInterface):
    def start_monitoring(self) -> bool:  
        # Monitoreo específico de archivos
```

---

## 🔧 Configuración y Personalización

### Sistema de Configuración por Plugin

Cada plugin mantiene su propia configuración:

```python
# plugins/detectors/behavior_detector/config.json
{
    "enabled": true,
    "detection_threshold": 0.7,
    "heuristic_analysis": true,
    "whitelist_enabled": true,
    "rule_engine": {
        "intelligence_mode": true,
        "behavioral_patterns": ["suspicious_file_access", "registry_tampering"]
    }
}

# plugins/detectors/keylogger_detector/config.json  
{
    "enabled": true,
    "detection_sensitivity": "high", 
    "monitor_hooks": true,
    "monitor_files": true,
    "api_monitoring": true,
    "confidence_threshold": 0.8
}

# plugins/detectors/ml_detector/config.json
{
    "enabled": true,
    "model_type": "onnx",
    "confidence_threshold": 0.8, 
    "feature_extraction": {
        "network_features": true,
        "process_features": true,
        "behavior_features": true
    }
}
```

### Configuración del Integration Engine

```python
# Configuración TDD/IAST/MDSD en integration_engine/plugin.py
self.tdd_config = {
    "enabled": True,
    "test_interval": 60,  # Tests cada 60 segundos
    "test_modules": [
        "tests/tdd_01_api_hooking_detection",
        "tests/tdd_02_port_detection"  
    ]
}

self.iast_config = {
    "enabled": True, 
    "scan_interval": 45,  # Análisis cada 45 segundos
    "vulnerability_checks": True
}

self.mdsd_config = {
    "enabled": True,
    "generation_interval": 120,  # Generación cada 2 minutos
    "auto_templates": True
}
```

---

## 🎯 Resumen del Funcionamiento

### Flujo Principal del Sistema

1. **Inicialización**: `UnifiedAntivirusEngine` coordina la carga de 8 plugins
2. **Monitoreo**: Monitores vigilan sistema y publican eventos via `EventBus`  
3. **Detección**: Detectores analizan eventos y calculan scores de amenaza
4. **Integración**: `IntegrationEngine` ejecuta TDD/IAST/MDSD en paralelo
5. **Respuesta**: Handlers procesan amenazas detectadas y generan alertas
6. **Logging**: Cada componente mantiene logs individuales para auditoría

### Características Clave

- **8 plugins totales**: 5 detectores + 3 handlers activos
- **10 streams de log**: Logging individual por componente
- **Arquitectura modular**: Plugins intercambiables usando Strategy Pattern  
- **Comunicación desacoplada**: EventBus implementa Observer Pattern
- **Detección multi-capa**: Behavior + ML + Network + Keylogger específico
- **Integración DevOps**: TDD + IAST + MDSD workers concurrentes
- **Thread-safety**: Logging concurrente sin bloqueos
- **Fallback automático**: Modelos ML con múltiples estrategias

**El sistema funciona como una orquesta coordinada donde cada plugin especializado contribuye su expertise al análisis global de amenazas, mientras que el Integration Engine mantiene las mejores prácticas de desarrollo y seguridad ejecutándose continuamente en background.**