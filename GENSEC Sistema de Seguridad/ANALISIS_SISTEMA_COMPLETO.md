# 🔍 Análisis Completo del Sistema Anti-Keylogger Unificado

## 📋 Índice

1. [Visión General del Sistema](#visión-general-del-sistema)
2. [Carpeta CONFIG](#carpeta-config)
3. [Carpeta CORE](#carpeta-core)
4. [Carpeta PLUGINS](#carpeta-plugins)
5. [Carpeta FRONTEND](#carpeta-frontend)
6. [Carpeta LOGS](#carpeta-logs)
7. [Carpeta MODELS](#carpeta-models)
8. [Carpeta TESTS](#carpeta-tests)
9. [Arquitectura y Flujo de Trabajo](#arquitectura-y-flujo-de-trabajo)

---

## 📌 Visión General del Sistema

El **Sistema Anti-Keylogger Unificado** es un sistema de seguridad profesional desarrollado en Python que implementa una arquitectura modular avanzada basada en plugins. Utiliza múltiples patrones de diseño (Facade, Observer, Factory, Template Method, Strategy) y metodologías modernas como TDD, IAST y MDSD.

### Características Principales

- **Detección Multi-Capa**: Combina análisis de comportamiento, Machine Learning (ONNX), y monitoreo de red
- **Arquitectura Modular**: Sistema de plugins extensible con 8 plugins principales
- **Interfaz Moderna**: Dear PyGui 2.1.0 con dashboard responsivo
- **Sistema de Eventos**: Event Bus para comunicación desacoplada
- **Logging Avanzado**: 10 archivos de log independientes
- **Testing Integrado**: TDD automático, IAST security testing, MDSD code generation

### Tecnologías Utilizadas

- **Python 3.x**: Lenguaje principal
- **Dear PyGui 2.1.0**: Interfaz gráfica moderna (GPU-accelerated)
- **ONNX Runtime**: Ejecución de modelos de Machine Learning
- **psutil**: Monitoreo de procesos y sistema
- **watchdog**: Monitoreo del sistema de archivos
- **pytest**: Framework de testing
- **pywin32**: APIs de Windows

---

## 📂 Carpeta CONFIG

**Ubicación**: `config/`  
**Propósito**: Centraliza todos los archivos de configuración del sistema

### Archivos de Configuración

#### 1. **unified_config.toml**
**Archivo**: `config/unified_config.toml`

Configuración principal del sistema en formato TOML. Define parámetros globales del sistema de seguridad.

**Contenido principal**:
- Configuración del motor principal
- Parámetros de plugins
- Umbrales de detección
- Configuración de logging

#### 2. **alerts_config.json**
**Archivo**: `config/alerts_config.json` (2.4 KB)

Configuración del sistema de alertas y notificaciones.

**Características**:
- Niveles de severidad (LOW, MEDIUM, HIGH, CRITICAL)
- Canales de notificación
- Plantillas de mensajes
- Reglas de escalamiento

#### 3. **ml_config.json**
**Archivo**: `config/ml_config.json` (2.3 KB)

Configuración de modelos de Machine Learning.

**Contenido**:
- Rutas a modelos ONNX
- Umbrales de predicción
- Configuración de inferencia
- Parámetros de feature extraction

#### 4. **plugins_config.json**
**Archivo**: `config/plugins_config.json` (2.9 KB)

Configuración específica de cada plugin del sistema.

**Estructura**:
```json
{
  "detectors": {
    "behavior_detector": { "enabled": true, "priority": 1 },
    "keylogger_detector": { "enabled": true, "priority": 2 },
    "ml_detector": { "enabled": true, "priority": 3 }
  },
  "monitors": { ... },
  "handlers": { ... }
}
```

#### 5. **security_config.json**
**Archivo**: `config/security_config.json` (2.3 KB)

Configuración de seguridad del sistema.

**Parámetros**:
- Políticas de cuarentena
- Configuración de cifrado
- Validación de entrada
- Permisos de archivos

#### 6. **logging_config.json**
**Archivo**: `config/logging_config.json` (2.7 KB)

Configuración del sistema de logging avanzado.

**Características**:
- Niveles de log por plugin
- Rotación de archivos
- Formato de salida
- Filtros personalizados

#### 7. **whitelist.json**
**Archivo**: `config/whitelist.json` (1.9 KB)

Lista blanca de procesos y archivos seguros.

**Contenido**:
- Procesos del sistema permitidos
- Rutas excluidas del escaneo
- Hashes de archivos confiables
- Dominios seguros

#### 8. **safe_profiles.json**
**Archivo**: `config/safe_profiles.json` (7.9 KB)

Perfiles de comportamiento seguro para procesos conocidos.

**Estructura**:
- Patrones de comportamiento normal
- Uso de recursos esperado
- APIs permitidas por proceso
- Conexiones de red legítimas

#### 9. **ui_config.json** y **ui_settings.json**
**Archivos**: `config/ui_config.json` (2.9 KB), `config/ui_settings.json` (2.1 KB)

Configuración de la interfaz de usuario.

**Parámetros**:
- Temas y colores
- Intervalos de actualización
- Configuración de gráficas
- Preferencias de usuario

### Utilidades de Configuración

#### **config_validator.py**
**Archivo**: `config/config_validator.py` (12.3 KB)

Script de validación de archivos de configuración.

**Funcionalidades**:
- Validación de sintaxis JSON/TOML
- Verificación de esquemas
- Detección de valores inválidos
- Sugerencias de corrección

### Documentación

- **README.md** (21.5 KB): Guía completa de configuración
- **GUIA_USUARIO_CONFIGURACION.md** (5.4 KB): Guía para usuarios finales
- **README_CONFIGURACION.md** (5.4 KB): Configuraciones avanzadas

---

## ⚙️ Carpeta CORE

**Ubicación**: `core/`  
**Propósito**: Núcleo del sistema - Motor principal y gestión de plugins

### Componentes Principales

#### 1. **engine.py** - Motor Principal
**Archivo**: `core/engine.py` (23 KB, 609 líneas)

**Patrón de Diseño**: Facade Pattern

**Clase Principal**: `UnifiedAntivirusEngine`

**Responsabilidades**:
- Coordinar todos los componentes del sistema
- Gestionar ciclo de vida del sistema de seguridad
- Orquestar plugins y detectores
- Proveer interfaz simplificada al sistema complejo

**Métodos Clave**:
```python
start_system(plugin_categories: List[str] = None) -> bool
shutdown_system() -> bool
restart_system() -> bool
activate_plugin(plugin_name: str) -> bool
deactivate_plugin(plugin_name: str) -> bool
get_system_status() -> dict
perform_system_scan() -> dict
analyze_memory_usage(process_name, memory_mb, threshold_mb) -> dict
combine_threat_results(detector_results) -> dict
```

**Características**:
- Manejo de señales del sistema (CTRL+C)
- Context manager (`with` statement)
- Monitoreo de estadísticas en tiempo real
- Event handlers para amenazas y errores

#### 2. **plugin_manager.py** - Gestor de Plugins
**Archivo**: `core/plugin_manager.py` (15.8 KB, 424 líneas)

**Patrones de Diseño**: Abstract Factory + Facade

**Clase Principal**: `PluginManager`

**Responsabilidades**:
- Descubrir plugins automáticamente
- Crear instancias de plugins (Factory)
- Gestionar activación/desactivación
- Coordinar familias de plugins

**Métodos Clave**:
```python
discover_and_load_plugins() -> bool
create_plugin_family(category: str) -> Dict
create_plugin(plugin_name: str, **kwargs) -> BasePlugin
activate_plugin(plugin_name: str) -> bool
deactivate_plugin(plugin_name: str) -> bool
activate_category(category: str) -> bool
activate_all_plugins() -> int
shutdown_all_plugins() -> bool
get_active_plugins() -> List[str]
get_plugins_by_category(category: str) -> List
```

**Categorías de Plugins**:
- **detectors**: Detectores de amenazas
- **monitors**: Monitores de sistema
- **handlers**: Manejadores de eventos

#### 3. **event_bus.py** - Bus de Eventos
**Archivo**: `core/event_bus.py` (8.6 KB)

**Patrón de Diseño**: Observer Pattern

**Clase Principal**: `EventBus`

**Responsabilidades**:
- Comunicación desacoplada entre componentes
- Sistema publish/subscribe
- Gestión de suscriptores por tipo de evento
- Thread-safe event handling

**Tipos de Eventos**:
```python
THREAT_DETECTED = "threat_detected"
PLUGIN_ERROR = "plugin_error"
SYSTEM_SCAN_COMPLETE = "system_scan_complete"
PROCESS_SUSPICIOUS = "process_suspicious"
NETWORK_ALERT = "network_alert"
FILE_MODIFIED = "file_modified"
```

**Métodos Clave**:
```python
subscribe(event_type: str, callback: Callable)
unsubscribe(event_type: str, callback: Callable)
publish(event: Event)
clear_all()
```

#### 4. **base_plugin.py** - Clase Base de Plugins
**Archivo**: `core/base_plugin.py` (5.9 KB)

**Patrón de Diseño**: Template Method

**Clase Principal**: `BasePlugin`

**Responsabilidades**:
- Definir ciclo de vida común de plugins
- Proporcionar métodos template
- Gestión de estado del plugin
- Logging integrado

**Métodos del Template**:
```python
initialize() -> bool  # Hook: Inicialización personalizada
execute() -> Any      # Hook: Lógica principal del plugin
cleanup() -> bool     # Hook: Limpieza de recursos
on_activate()         # Template method
on_deactivate()       # Template method
get_status() -> dict
```

#### 5. **interfaces.py** - Interfaces de Plugins
**Archivo**: `core/interfaces.py` (11.6 KB)

**Propósito**: Define contratos para diferentes tipos de plugins

**Interfaces Principales**:
- `DetectorInterface`: Para plugins detectores
- `MonitorInterface`: Para plugins monitores
- `HandlerInterface`: Para plugins manejadores

**Métodos Comunes**:
```python
detect(data: Any) -> dict
handle_event(event: Event)
get_detection_result() -> dict
```

#### 6. **plugin_registry.py** - Registro de Plugins
**Archivo**: `core/plugin_registry.py` (11.7 KB)

**Patrón de Diseño**: Registry Pattern

**Clase Principal**: `PluginRegistry`

**Responsabilidades**:
- Registro centralizado de plugins disponibles
- Metadatos de plugins
- Búsqueda y consulta de plugins
- Validación de dependencias

**Métodos**:
```python
register(plugin_class, metadata: dict)
unregister(plugin_name: str)
get_plugin_class(plugin_name: str)
get_all_plugins() -> List
get_plugins_by_category(category: str) -> List
```

#### 7. **detector_engine.py** - Motor de Detección
**Archivo**: `core/detector_engine.py` (19.6 KB)

**Responsabilidades**:
- Orquestar múltiples detectores
- Coordinar análisis de amenazas
- Agregar resultados de detección

#### 8. **consensus_engine.py** - Motor de Consenso
**Archivo**: `core/consensus_engine.py` (15.1 KB)

**Responsabilidades**:
- Combinar resultados de múltiples detectores
- Calcular nivel de riesgo consensuado
- Resolver conflictos entre detectores
- Ponderación de confianza

**Algoritmo**:
```python
def calculate_consensus(results: List[dict]) -> dict:
    # Weighted voting system
    # Confidence-based aggregation
    # Risk level determination
    return {
        "final_risk_level": "HIGH|MEDIUM|LOW",
        "confidence": 0.0-1.0,
        "contributing_detectors": [...]
    }
```

#### 9. **memory_monitor.py** - Monitor de Memoria
**Archivo**: `core/memory_monitor.py` (15.3 KB)

**Responsabilidades**:
- Monitorear uso de memoria de procesos
- Detectar anomalías de memoria
- Alertar sobre consumo excesivo
- Análisis de patrones de memoria

#### 10. **resource_monitor.py** - Monitor de Recursos
**Archivo**: `core/resource_monitor.py` (18.6 KB)

**Responsabilidades**:
- Monitorear CPU, disco, red
- Detectar uso anómalo de recursos
- Gestión de thresholds
- Métricas de rendimiento

#### 11. **simple_engine.py** - Motor Simplificado
**Archivo**: `core/simple_engine.py` (14.2 KB)

**Propósito**: Versión simplificada del motor para testing y desarrollo

### Documentación Core

**README.md** (26.4 KB): Documentación completa de la arquitectura del core

---

## 🔌 Carpeta PLUGINS

**Ubicación**: `plugins/`  
**Propósito**: Sistema modular de plugins para detección, monitoreo y manejo de amenazas

### Estructura de Plugins

```
plugins/
├── detectors/      # Plugins de detección de amenazas
├── monitors/       # Plugins de monitoreo del sistema
├── handlers/       # Plugins de manejo de eventos y respuestas
└── shared/         # Código compartido entre plugins
```

---

### 🔍 DETECTORS - Detectores de Amenazas

**Ubicación**: `plugins/detectors/`  
**Total**: 7 subdirectorios (6 detectores + 1 carpeta generated)

#### 1. **Behavior Detector** - Detector de Comportamiento
**Ubicación**: `plugins/detectors/behavior_detector/`

**Propósito**: Analiza el comportamiento de procesos para detectar actividades sospechosas

**Archivos Principales**:
- `behavior_detector_plugin.py`: Plugin principal
- `behavior_analyzer.py`: Analizador de comportamiento
- `pattern_matcher.py`: Coincidencia de patrones maliciosos
- `test_behavior_detector.py`: Tests unitarios

**Detecciones**:
- Patrones de comportamiento malicioso
- Uso anómalo de APIs de Windows
- Inyección de código
- Elevación de privilegios
- Persistencia sospechosa

**Métricas**:
- API calls monitoreadas
- Patrones de comportamiento conocidos
- Score de sospecha (0.0-1.0)

#### 2. **Keylogger Detector** - Detector de Keyloggers
**Ubicación**: `plugins/detectors/keylogger_detector/`

**Propósito**: Detección especializada de keyloggers usando análisis de hooks y comportamiento

**Archivos Principales**:
- `keylogger_detector_plugin.py`: Plugin principal
- `hook_detector.py`: Detección de hooks de teclado
- `log_file_detector.py`: Detección de archivos de log sospechosos
- `api_monitor.py`: Monitoreo de APIs de captura de teclado
- `test_keylogger_detector.py`: Tests

**Técnicas de Detección**:
1. **Hook Detection**: Detección de hooks de Windows (SetWindowsHookEx, GetAsyncKeyState)
2. **API Monitoring**: Monitoreo de GetKeyState, GetForegroundWindow
3. **Log File Analysis**: Búsqueda de archivos .log con patrones de keylogging
4. **Clipboard Monitoring**: Detección de captura de portapapeles
5. **Screen Capture Detection**: Identificación de capturas de pantalla sospechosas

**Indicadores de Amenaza**:
- Uso de APIs de hooking
- Archivos de log con timestamps y teclas
- Captura continua de teclado
- Envío de datos por red

#### 3. **ML Detector** - Detector de Machine Learning
**Ubicación**: `plugins/detectors/ml_detector/`

**Propósito**: Detección basada en modelos de Machine Learning (ONNX)

**Archivos Principales**:
- `ml_detector_plugin.py`: Plugin principal
- `feature_extractor.py`: Extracción de características
- `onnx_inferencer.py`: Inferencia con modelos ONNX
- `model_loader.py`: Carga de modelos
- `test_ml_detector.py`: Tests

**Modelos Utilizados**:
- `keylogger_model_large_*.onnx`: Modelo principal (51 MB)
- `rf_large_model_*.pkl`: Random Forest (104 MB)

**Features Extraídas**:
- Uso de memoria
- CPU usage patterns
- API calls frequency
- Network connections
- File operations
- Thread count
- Handle count

**Proceso de Inferencia**:
```python
1. Extract features from process
2. Normalize features
3. Run ONNX inference
4. Apply threshold (default: 0.5)
5. Return prediction + confidence
```

#### 4. **Network Detector** - Detector de Red
**Ubicación**: `plugins/detectors/network_detector/`

**Propósito**: Análisis de tráfico de red y detección de conexiones maliciosas

**Archivos Principales**:
- `network_detector_plugin.py`: Plugin principal
- `connection_monitor.py`: Monitoreo de conexiones
- `traffic_analyzer.py`: Análisis de tráfico
- `dns_analyzer.py`: Análisis DNS
- `port_scanner_detector.py`: Detección de port scanning
- `threat_intel_lookup.py`: Consulta de threat intelligence
- `test_network_detector.py`: Tests

**Detecciones**:
1. **Conexiones Sospechosas**: IPs maliciosas conocidas
2. **Port Scanning**: Detección de escaneo de puertos
3. **DNS Anomalies**: Consultas DNS sospechosas
4. **Data Exfiltration**: Grandes cantidades de datos salientes
5. **C&C Communication**: Comunicación con Command & Control servers
6. **DGA Detection**: Generación algorítmica de dominios

**Threat Intelligence**:
- Base de datos de IPs maliciosas (`threat_intel/malicious_ips.txt`)
- Lista de dominios sospechosos (`threat_intel/domains.txt`)
- Actualización periódica

#### 5. **IAST Detector** - Interactive Application Security Testing
**Ubicación**: `plugins/detectors/iast_detector/`

**Propósito**: Testing de seguridad interactivo en tiempo real

**Archivos Principales**:
- `iast_detector_plugin.py`: Plugin principal
- `vulnerability_scanner.py`: Escáner de vulnerabilidades
- `sql_injection_detector.py`: Detección de SQL Injection
- `xss_detector.py`: Detección de XSS
- `security_tester.py`: Tests de seguridad
- `test_iast_detector.py`: Tests unitarios

**Vulnerabilidades Detectadas**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Buffer Overflow
- Insecure Deserialization

**Frecuencia**: Escaneo automático cada 45 segundos

**Log**: `logs/iast_security.log`

#### 6. **Integration Engine** - Motor de Integración
**Ubicación**: `plugins/detectors/integration_engine/`

**Propósito**: Integración de TDD, IAST y MDSD en el sistema

**Archivos Principales**:
- `integration_engine_plugin.py`: Plugin principal
- `tdd_runner.py`: Ejecutor de tests TDD
- `iast_runner.py`: Ejecutor de tests IAST
- `mdsd_generator.py`: Generador de código MDSD

**Componentes**:

##### TDD Integration (Test-Driven Development)
- Ejecución automática de tests cada 60 segundos
- Suite de tests: `tdd_01_api_hooking_detection`, `tdd_02_port_detection`
- Framework: pytest
- Log: `logs/tdd_integration.log`

##### IAST Integration (Interactive Security Testing)
- Análisis de seguridad cada 45 segundos
- Log: `logs/iast_security.log`
- Detección de vulnerabilidades en tiempo real

##### MDSD Integration (Model-Driven Software Development)
- Generación automática de templates cada 120 segundos
- Templates: Ransomware Detector, Trojan Detector, Rootkit Detector, Spyware Detector
- Log: `logs/mdsd_generator.log`
- Workflow engine de generación de código

**Arquitectura**:
```python
IntegrationEnginePlugin
├── TDD Worker (Thread)
├── IAST Worker (Thread)
├── MDSD Worker (Thread)
└── Main Controller
```

---

### 📡 MONITORS - Monitores de Sistema

**Ubicación**: `plugins/monitors/`  
**Total**: 3 monitores principales

#### 1. **File Monitor** - Monitor de Archivos
**Ubicación**: `plugins/monitors/file_monitor/`

**Propósito**: Monitoreo del sistema de archivos en tiempo real

**Archivos**:
- `file_monitor_plugin.py`
- `watchdog_handler.py`: Handler de watchdog
- `file_analyzer.py`: Análisis de archivos modificados
- `test_file_monitor.py`

**Detecciones**:
- Creación de archivos sospechosos
- Modificación de archivos del sistema
- Eliminación de archivos críticos
- Renombrado masivo (ransomware)
- Escrituras en directorios protegidos

**Tecnología**: watchdog library

#### 2. **Network Monitor** - Monitor de Red
**Ubicación**: `plugins/monitors/network_monitor/`

**Propósito**: Monitoreo continuo de conexiones de red

**Archivos**:
- `network_monitor_plugin.py`
- `connection_tracker.py`: Rastreo de conexiones
- `bandwidth_monitor.py`: Monitoreo de ancho de banda
- `test_network_monitor.py`

**Métricas**:
- Conexiones activas
- Bytes sent/received
- Puertos abiertos
- Velocidad de transferencia

#### 3. **Process Monitor** - Monitor de Procesos
**Ubicación**: `plugins/monitors/process_monitor/`

**Propósito**: Monitoreo de procesos del sistema

**Archivos**:
- `process_monitor_plugin.py`
- `process_tracker.py`
- `test_process_monitor.py`

**Información Capturada**:
- Procesos nuevos/terminados
- Uso de CPU/RAM
- Threads activos
- Handles abiertos
- Imagen del ejecutable
- Línea de comandos

---

### ⚡ HANDLERS - Manejadores de Eventos

**Ubicación**: `plugins/handlers/`  
**Total**: 3 handlers principales

#### 1. **Alert Manager** - Gestor de Alertas
**Ubicación**: `plugins/handlers/alert_manager/`

**Propósito**: Gestión centralizada de alertas y notificaciones

**Archivos**:
- `alert_manager_plugin.py`
- `notification_dispatcher.py`: Dispatcher de notificaciones
- `alert_formatter.py`: Formateo de alertas
- `test_alert_manager.py`

**Canales de Notificación**:
- Sistema de logs
- Notificaciones de Windows
- Email (configurable)
- Webhooks (configurable)

**Niveles de Severidad**:
- CRITICAL: Amenaza inmediata
- HIGH: Alta prioridad
- MEDIUM: Prioridad media
- LOW: Informacional

#### 2. **Logger Handler** - Manejador de Logging
**Ubicación**: `plugins/handlers/logger_handler/`

**Propósito**: Logging estructurado de eventos del sistema

**Archivos**:
- `logger_handler_plugin.py`
- `structured_logger.py`: Logger estructurado
- `log_formatter.py`: Formateador de logs
- `test_logger_handler.py`

**Características**:
- UTF-8 encoding
- Logging estructurado (JSON)
- Rotación automática
- Thread-safe
- Múltiples handlers

#### 3. **Quarantine Handler** - Gestor de Cuarentena
**Ubicación**: `plugins/handlers/quarantine_handler/`

**Propósito**: Aislamiento seguro de archivos maliciosos

**Archivos**:
- `quarantine_handler_plugin.py`
- `file_isolator.py`: Aislador de archivos
- `encryption_manager.py`: Cifrado de archivos en cuarentena
- `test_quarantine_handler.py`

**Funcionalidades**:
- Movimiento seguro a cuarentena
- Cifrado de archivos peligrosos
- Registro de archivos en cuarentena
- Restauración controlada
- Eliminación permanente

---

### 📚 Documentación y Recursos de Plugins

- **README.md** (6.3 KB): Documentación general de plugins
- **upgrade_intelligence.py** (16.6 KB): Sistema de actualizaciones de inteligencia de amenazas
- **backup_configs/**: Backups de configuraciones de plugins
- **shared/**: Código compartido entre plugins

---

## 🖥️ Carpeta FRONTEND

**Ubicación**: `frontend/`  
**Propósito**: Interfaz gráfica de usuario del sistema de seguridad

### Componentes del Frontend

#### 1. **main.py** - Aplicación Principal
**Archivo**: `frontend/main.py` (47.4 KB, 1300+ líneas)

**Framework**: Dear PyGui 2.1.0

**Responsabilidades**:
- Inicialización de la interfaz gráfica
- Gestión del window manager
- Coordinación de componentes UI
- Comunicación con el backend

**Características**:
- Dashboard responsivo
- GPU-accelerated rendering
- Thread-safe UI updates
- Event loop integration

#### 2. **Componentes** (`components/`)

**Ubicación**: `frontend/components/`

##### **dashboard.py** - Panel Principal
**Archivo**: `frontend/components/dashboard.py` (17.7 KB)

**Características**:
- Métricas en tiempo real
- Gráficas de rendimiento
- Estado de plugins
- Contador de amenazas
- Uptime del sistema

**Widgets**:
- Tarjetas de métricas (responsive)
- Gráficos de línea y barras
- Tablas de información
- Indicadores de estado

##### **threat_viewer.py** - Visor de Amenazas
**Archivo**: `frontend/components/threat_viewer.py` (40.2 KB)

**Características**:
- Lista de amenazas detectadas
- Detalles de cada amenaza
- Árbol de decisión de análisis (en español)
- Acciones sobre amenazas (cuarentena, ignorar)

**Información Mostrada**:
- Nombre del proceso
- PID
- Nivel de riesgo
- Confianza de detección
- Detectores que contribuyeron
- Acciones recomendadas

##### **logs_viewer.py** - Visor de Logs
**Archivo**: `frontend/components/logs_viewer.py` (9.9 KB)

**Características**:
- Vista de logs en tiempo real
- Filtrado por nivel (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Filtrado por plugin
- Códigos de color por severidad
- Auto-scroll

##### **realtime_monitor.py** - Monitor en Tiempo Real
**Archivo**: `frontend/components/realtime_monitor.py` (12.1 KB)

**Características**:
- Monitoreo de procesos activos
- Uso de CPU y RAM en tiempo real
- Network activity
- File system activity

##### **settings.py** - Panel de Configuración
**Archivo**: `frontend/components/settings.py` (29.6 KB)

**Características**:
- Configuración de plugins
- Modos preset (Básico, Avanzado, Experto)
- Activación/desactivación de detectores
- Configuración de umbrales
- Guardar/cargar configuraciones

**Modos Preset**:
1. **Básico**: Solo detectores esenciales
2. **Avanzado**: Detectores + monitores
3. **Experto**: Todas las características + logging extendido

#### 3. **Temas** (`themes/`)

**Ubicación**: `frontend/themes/`

**Archivos**:
- `dark_theme.py`: Tema oscuro (default)
- `light_theme.py`: Tema claro

**Características**:
- Paleta de colores cohesiva
- Glassmorphism effects
- Gradientes suaves
- Tipografía moderna

#### 4. **Utilidades** (`utils/`)

**Ubicación**: `frontend/utils/`

**Archivos**:
- `ui_helpers.py`: Funciones auxiliares de UI
- `data_formatters.py`: Formateo de datos para visualización

### Mejoras Recientes del Frontend

#### ✅ Dashboard Responsivo Completo
- Adaptación automática al tamaño de pantalla
- Cálculos de viewport dinámicos
- Tarjetas que se escalan proporcionalmente
- Gráficos redimensionables

#### ✅ Sistema de Modals Mejorado
- Botón "X" funcional en modales
- Callbacks de cierre correctos
- Sin errores de dpg.parent()
- Rendimiento optimizado

#### ✅ Interfaz en Español
- Traducción completa
- Árboles de decisión detallados
- Terminología técnica precisa

#### ✅ Configuración Dinámica
- Modos preset
- Indicadores visuales de estado activo
- Sincronización con backend

### Logs del Frontend

**Log Principal**: `logs/frontend.log`

Registra:
- Eventos de UI
- Errores de renderizado
- Interacciones del usuario
- Actualización de componentes

### Documentación

**README.md** (12.4 KB): Documentación completa del frontend

---

## 📝 Carpeta LOGS

**Ubicación**: `logs/`  
**Propósito**: Almacenamiento centralizado de todos los logs del sistema

### Archivos de Log

El sistema genera **10 archivos de log independientes**:

#### 1. **antivirus.log**
**Tamaño**: ~8.3 MB (log principal)

**Contenido**:
- Eventos del motor principal
- Start/stop del sistema
- Activación/desactivación de plugins
- Estadísticas del sistema
- Errores generales

#### 2. **frontend.log**
**Contenido**:
- Eventos de la interfaz Dear PyGui
- Interacciones del usuario
- Actualización de componentes
- Errores de UI

#### 3. **behavior_detector.log**
**Tamaño**: ~59 KB

**Contenido**:
- Análisis de comportamiento de procesos
- Patrones detectados
- Scores de sospecha
- APIs monitoreadas

#### 4. **keylogger_detector.log**
**Tamaño**: ~31 KB

**Contenido**:
- Detección de hooks
- Archivos de log sospechosos
- APIs de captura de teclado
- Detecciones positivas

#### 5. **ml_detector.log**
**Tamaño**: ~30 KB

**Contenido**:
- Inferencias de modelos ONNX
- Feature extraction
- Predicciones y confianza
- Carga de modelos

#### 6. **network_detector.log**
**Tamaño**: ~80 KB

**Contenido**:
- Conexiones analizadas
- IPs maliciosas detectadas
- Análisis de DNS
- Traffic anomalies

#### 7. **integration_engine.log**
**Tamaño**: ~13 KB

**Contenido**:
- Coordinación de TDD/IAST/MDSD
- Estado de workers
- Ciclos de ejecución
- Errores de integración

#### 8. **tdd_integration.log**
**Tamaño**: ~32 KB

**Contenido**:
```
✅ Tests en tests/tdd_01_api_hooking_detection: PASSED
✅ Tests en tests/tdd_02_port_detection: PASSED
✅ Ciclo TDD completado
📊 ===== 8 passed in 5.23s =====
```

#### 9. **iast_security.log**
**Tamaño**: ~45 KB

**Contenido**:
```
✅ Análisis IAST: Sin vulnerabilidades críticas
🔍 SQL Injection tests: OK
🔍 XSS tests: OK
📊 ===== 16 passed in 10.98s =====
```

#### 10. **mdsd_generator.log**
**Tamaño**: ~29 KB

**Contenido**:
```
📝 Generando template: Ransomware Detector
📝 Generando template: Trojan Detector
📝 Generando template: Rootkit Detector
✅ Ciclo MDSD completado
```

### Características del Sistema de Logs

#### Niveles de Logging
- **DEBUG**: Información detallada de desarrollo
- **INFO**: Eventos normales del sistema
- **WARNING**: Eventos sospechosos
- **ERROR**: Errores recuperables
- **CRITICAL**: Errores críticos

#### Características Técnicas
- ✅ **UTF-8 Encoding**: Soporte para emojis y caracteres especiales
- ✅ **Rotación Automática**: Prevención de archivos excesivamente grandes
- ✅ **Thread-safe**: Logging concurrente sin bloqueos
- ✅ **Filtrado**: Configuración independiente por plugin
- ✅ **Monitoreo en Tiempo Real**: `monitor_all_logs.py`

### Herramientas de Monitoreo

#### **monitor_all_logs.py**
**Propósito**: Monitor en tiempo real de todos los logs simultáneamente

**Características**:
- Monitoreo de 10 archivos simultáneos
- Códigos de color por tipo de plugin:
  - 🟢 Verde: TDD Integration
  - 🔵 Azul: IAST Security
  - 🟡 Amarillo: MDSD Generator
  - 🔴 Rojo: Detectores de amenazas
  - ⚪ Blanco: Sistema general
- Auto-detección de nuevos logs
- Filtrado por severidad

**Uso**:
```bash
python monitor_all_logs.py
```

### Documentación

**README.md** (10 KB): Guía del sistema de logging

---

## 🧠 Carpeta MODELS

**Ubicación**: `models/`  
**Propósito**: Almacenamiento de modelos de Machine Learning

### Modelos Disponibles

#### 1. **keylogger_model_large_20250918_112840.onnx**
**Tamaño**: 51.5 MB

**Descripción**: Modelo principal de detección de keyloggers en formato ONNX

**Características**:
- Arquitectura: Red neuronal profunda
- Inputs: Features de procesos (memoria, CPU, APIs, etc.)
- Outputs: Probabilidad [benign, malicious]
- Threshold: 0.5 (configurable)

**Metadatos**: `onnx_metadata_large_20250918_112840.json` (10 KB)

#### 2. **modelo_keylogger_from_datos.onnx**
**Tamaño**: 51.5 MB

**Descripción**: Modelo alternativo entrenado desde datos reales

#### 3. **rf_large_model_20250918_112442.pkl**
**Tamaño**: 104.5 MB

**Descripción**: Modelo Random Forest en formato pickle

**Características**:
- Ensemble learning
- Alta precisión
- Interpretable
- Usado como modelo de validación

#### 4. **label_classes.json**
**Tamaño**: 32 bytes

**Contenido**:
```json
["benign", "malicious"]
```

### Proceso de Inferencia

```python
# 1. Cargar modelo ONNX
session = onnxruntime.InferenceSession("keylogger_model_large.onnx")

# 2. Extraer features del proceso
features = extract_features(process)
# Features: [memory_mb, cpu_percent, thread_count, handle_count, 
#            api_hooks, network_connections, file_operations, ...]

# 3. Normalizar features
normalized = normalize(features)

# 4. Ejecutar inferencia
outputs = session.run(None, {"input": normalized})

# 5. Obtener predicción
probabilities = outputs[0]
prediction = "malicious" if probabilities[1] > 0.5 else "benign"
confidence = probabilities[1]
```

### Entrenamiento

**Dataset**: Recolección de features de procesos benignos y maliciosos conocidos

**Features (87 total)**:
- Uso de memoria (MB)
- CPU usage (%)
- Thread count
- Handle count
- API calls frequency
- Network connections
- Registry operations
- File operations
- Keyboard/mouse hooks
- Clipboard access
- Screen capture

**Métricas de Evaluación**:
- Precisión: ~94%
- Recall: ~92%
- F1-Score: ~93%
- False Positives: <5%

### Actualización de Modelos

Los modelos se actualizan periódicamente con:
- Nuevas muestras de malware
- Refinamiento de features
- Re-entrenamiento con datos frescos

### Documentación

**README.md** (13 KB): Guía completa de modelos de ML

---

## 🧪 Carpeta TESTS

**Ubicación**: `tests/`  
**Propósito**: Suite completa de pruebas del sistema

### Estructura de Tests

#### Tests TDD (Test-Driven Development)

##### 1. **tdd_01_api_hooking_detection**
**Ubicación**: `tests/tdd_01_api_hooking_detection/`

**Propósito**: Tests de detección de API hooking

**Archivos**:
- `test_hook_detection.py`: Tests de hooks de Windows
- `README.md`: Documentación del test

**Tests Incluidos**:
```python
test_detect_keyboard_hook()      # Detección de hooks de teclado
test_detect_mouse_hook()          # Detección de hooks de ratón
test_detect_api_monitoring()      # Monitoreo de APIs sospechosas
test_false_positive_rate()        # Tasa de falsos positivos
```

**Ejecución**:
```bash
pytest tests/tdd_01_api_hooking_detection/
```

##### 2. **tdd_02_port_detection**
**Ubicación**: `tests/tdd_02_port_detection/`

**Propósito**: Tests de detección de puertos sospechosos

**Archivos**:
- `test_port_scanner.py`: Tests de escaneo de puertos
- `README.md`: Documentación

**Tests Incluidos**:
```python
test_detect_suspicious_ports()    # Puertos sospechosos
test_detect_port_scanning()       # Scanning behavior
test_legitimate_services()        # Servicios legítimos
test_port_binding()               # Binding sospechoso
```

##### 3. **tdd_03_safe_process_validation**
**Ubicación**: `tests/tdd_03_safe_process_validation/`

**Propósito**: Validación de procesos seguros (whitelist)

**Tests**:
```python
test_whitelist_processes()        # Procesos en whitelist
test_system_processes()           # Procesos del sistema
test_false_detection_rate()       # Tasa de falsa detección
```

##### 4. **tdd_04_cpu_monitoring**
**Ubicación**: `tests/tdd_04_cpu_monitoring/`

**Propósito**: Tests de monitoreo de CPU

##### 5. **tdd_05_detector_initialization**
**Ubicación**: `tests/tdd_05_detector_initialization/`

**Propósito**: Tests de inicialización de detectores

##### 6. **tdd_06_feature_extraction**
**Ubicación**: `tests/tdd_06_feature_extraction/`

**Propósito**: Tests de extracción de features para ML

##### 7. **tdd_07_consensus**
**Ubicación**: `tests/tdd_07_consensus/`

**Propósito**: Tests del motor de consenso

##### 8. **tdd_08_memory_threshold**
**Ubicación**: `tests/tdd_08_memory_threshold/`

**Propósito**: Tests de umbrales de memoria

#### Tests IAST (Interactive Application Security Testing)

**Ubicación**: `tests/iast_tests/`

**Propósito**: Tests de seguridad interactivos

**Tests Incluidos**:
- SQL Injection detection
- XSS detection
- Command Injection
- Path Traversal
- Buffer Overflow
- Insecure Deserialization

#### Tests de Integración

**Ubicación**: `tests/integration/`

**Propósito**: Tests de integración completa del sistema

**Archivos**:
- `test_full_system.py`: Test del sistema completo
- `test_plugin_integration.py`: Integración de plugins

### Configuración de Tests

#### **pytest.ini**
**Archivo**: `pytest.ini` (1.2 KB)

```ini
[pytest]
testpaths = tests plugins
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    detector: Tests de detectores
    monitor: Tests de monitores
    integration: Tests de integración
```

### Ejecución de Tests

#### Tests Individuales
```bash
# Test específico
pytest tests/tdd_01_api_hooking_detection/

# Todos los tests TDD
pytest tests/tdd_*/

# Con coverage
pytest --cov=core --cov=plugins tests/
```

#### Tests Automáticos (Integration Engine)
El Integration Engine ejecuta tests automáticamente cada 60 segundos:
- Suite TDD completa
- Logs en `logs/tdd_integration.log`

#### Ejecutor de Todos los Tests
```bash
python run_all_tdd_tests.py
```

### Métricas de Cobertura

**Cobertura Actual**:
- Core: ~85%
- Plugins: ~78%
- Frontend: ~65%
- Total: ~76%

### Documentación

- **README.md** (12.9 KB): Documentación general de tests
- **GUIA_IMPLEMENTACION_TDD.md** (4.6 KB): Guía de implementación TDD

---

## 🏗️ Arquitectura y Flujo de Trabajo

### Patrones de Diseño Implementados

#### 1. **Facade Pattern**
**Implementado en**: `core/engine.py`

**Propósito**: Simplificar la interfaz compleja del sistema

**Clase**: `UnifiedAntivirusEngine`

**Beneficios**:
- Interfaz única para el sistema completo
- Oculta complejidad interna
- Facilita uso del sistema

#### 2. **Observer Pattern**
**Implementado en**: `core/event_bus.py`

**Propósito**: Comunicación desacoplada entre componentes

**Componentes**:
- Event Bus (Subject)
- Plugins (Observers)
- Events (Messages)

**Flujo**:
```
Publisher → Event Bus → Subscribers
```

#### 3. **Factory Pattern**
**Implementado en**: `core/plugin_manager.py`

**Propósito**: Creación dinámica de plugins

**Métodos Factory**:
- `create_plugin()`
- `create_plugin_family()`

#### 4. **Template Method**
**Implementado en**: `core/base_plugin.py`

**Propósito**: Definir ciclo de vida común de plugins

**Template**:
```python
on_activate():
    initialize()  # Hook
    execute()     # Hook
    
on_deactivate():
    cleanup()     # Hook
```

#### 5. **Strategy Pattern**
**Implementado en**: Detectores

**Propósito**: Diferentes estrategias de detección intercambiables

**Estrategias**:
- Behavior-based detection
- ML-based detection
- Network-based detection
- Signature-based detection

#### 6. **Registry Pattern**
**Implementado en**: `core/plugin_registry.py`

**Propósito**: Registro centralizado de plugins

### Flujo de Funcionamiento

```
┌─────────────────────────────────────────────────────────────┐
│ 1. INICIALIZACIÓN                                           │
├─────────────────────────────────────────────────────────────┤
│ backend_launcher.py / production_launcher.py                │
│         ↓                                                   │
│ UnifiedAntivirusEngine.__init__()                          │
│         ↓                                                   │
│ PluginManager.discover_and_load_plugins()                  │
│         ↓                                                   │
│ Registro de plugins en PluginRegistry                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 2. ACTIVACIÓN                                               │
├─────────────────────────────────────────────────────────────┤
│ Engine.start_system(plugin_categories)                     │
│         ↓                                                   │
│ PluginManager.activate_category("detectors")              │
│ PluginManager.activate_category("monitors")               │
│ PluginManager.activate_category("handlers")               │
│         ↓                                                   │
│ Para cada plugin:                                          │
│   - plugin.on_activate()                                    │
│   - plugin.initialize()                                     │
│   - Suscripción al Event Bus                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 3. MONITOREO (Loop Continuo)                               │
├─────────────────────────────────────────────────────────────┤
│ ProcessMonitor detecta nuevo proceso                       │
│         ↓                                                   │
│ event_bus.publish(Event("process_created", data))         │
│         ↓                                                   │
│ Todos los detectores suscritos reciben el evento          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 4. DETECCIÓN                                                │
├─────────────────────────────────────────────────────────────┤
│ BehaviorDetector.detect(process) → score: 0.7             │
│ KeyloggerDetector.detect(process) → score: 0.8           │
│ MLDetector.detect(process) → score: 0.9                   │
│ NetworkDetector.detect(process) → score: 0.6             │
│         ↓                                                   │
│ ConsensusEngine.calculate_consensus(results)              │
│         ↓                                                   │
│ final_risk_level: HIGH, confidence: 0.85                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 5. MANEJO DE AMENAZA                                        │
├─────────────────────────────────────────────────────────────┤
│ event_bus.publish(Event("threat_detected", threat_data))  │
│         ↓                                                   │
│ AlertManager recibe evento → genera alerta                │
│ LoggerHandler recibe evento → registra en log             │
│ QuarantineHandler recibe evento → mueve a cuarentena      │
│         ↓                                                   │
│ Frontend actualiza UI con nueva amenaza                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ 6. INTEGRACIÓN CONTINUA (Background)                       │
├─────────────────────────────────────────────────────────────┤
│ IntegrationEngine Worker Threads:                         │
│   ┌─────────────────────────────────────┐                │
│   │ TDD Worker (cada 60s)               │                │
│   │   - pytest tests/tdd_*              │                │
│   │   - Log: tdd_integration.log         │                │
│   ├─────────────────────────────────────┤                │
│   │ IAST Worker (cada 45s)              │                │
│   │   - Security scans                   │                │
│   │   - Log: iast_security.log           │                │
│   ├─────────────────────────────────────┤                │
│   │ MDSD Worker (cada 120s)             │                │
│   │   - Code generation                  │                │
│   │   - Log: mdsd_generator.log          │                │
│   └─────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

### Comunicación Entre Componentes

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  Monitors    │──────▶│  Event Bus   │◀──────│  Detectors   │
└──────────────┘       └──────────────┘       └──────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │   Handlers   │
                       └──────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │   Frontend   │
                       └──────────────┘
```

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────┐
│                    UNIFIED ANTIVIRUS                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐   │
│  │              UnifiedAntivirusEngine                │   │
│  │                 (Facade Pattern)                    │   │
│  └────────────────────────────────────────────────────┘   │
│                          │                                  │
│       ┌──────────────────┼──────────────────┐             │
│       ▼                  ▼                  ▼             │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐       │
│  │ Plugin   │      │  Event   │      │Consensus │       │
│  │ Manager  │      │   Bus    │      │  Engine  │       │
│  └──────────┘      └──────────┘      └──────────┘       │
│       │                  │                                  │
│       ▼                  ▼                                  │
│  ┌─────────────────────────────────────────┐              │
│  │            Plugin Ecosystem              │              │
│  ├─────────────────────────────────────────┤              │
│  │ Detectors:                              │              │
│  │  - BehaviorDetector                     │              │
│  │  - KeyloggerDetector                    │              │
│  │  - MLDetector                           │              │
│  │  - NetworkDetector                      │              │
│  │  - IASTDetector                         │              │
│  │  - IntegrationEngine                    │              │
│  ├─────────────────────────────────────────┤              │
│  │ Monitors:                               │              │
│  │  - ProcessMonitor                       │              │
│  │  - FileMonitor                          │              │
│  │  - NetworkMonitor                       │              │
│  ├─────────────────────────────────────────┤              │
│  │ Handlers:                               │              │
│  │  - AlertManager                         │              │
│  │  - LoggerHandler                        │              │
│  │  - QuarantineHandler                    │              │
│  └─────────────────────────────────────────┘              │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────┐              │
│  │           Frontend (Dear PyGui)         │              │
│  │  - Dashboard                            │              │
│  │  - ThreatViewer                         │              │
│  │  - LogsViewer                           │              │
│  │  - Settings                             │              │
│  └─────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

### Tecnologías por Capa

| Capa | Tecnología | Propósito |
|------|------------|-----------|
| **Core Engine** | Python 3.x | Motor principal |
| **Event System** | Observer Pattern | Comunicación |
| **ML Detection** | ONNX Runtime | Inferencia de modelos |
| **Process Monitoring** | psutil | Monitoreo de procesos |
| **File Monitoring** | watchdog | Sistema de archivos |
| **Network** | socket, psutil | Conexiones de red |
| **Frontend** | Dear PyGui 2.1.0 | Interfaz gráfica |
| **Testing** | pytest | Tests automáticos |
| **Logging** | logging (Python) | Sistema de logs |
| **Configuration** | TOML, JSON | Configuración |

---

## 📊 Resumen Ejecutivo

### Estadísticas del Sistema

- **Líneas de Código**: ~15,000 LOC (Python)
- **Plugins**: 8 plugins principales
- **Archivos de Log**: 10 independientes
- **Modelos ML**: 3 modelos (156 MB total)
- **Tests**: 50+ test cases
- **Archivos de Configuración**: 9 archivos JSON/TOML
- **Documentación**: 60+ archivos Markdown

### Cobertura Funcional

| Característica | Estado | Descripción |
|----------------|--------|-------------|
| Detección de Keyloggers | ✅ 100% | Hook detection, API monitoring, log file analysis |
| Machine Learning | ✅ 100% | ONNX inference, 94% accuracy |
| Network Analysis | ✅ 100% | Connection monitoring, threat intelligence |
| Behavior Analysis | ✅ 100% | Pattern matching, API monitoring |
| Security Testing | ✅ 100% | IAST automation, vulnerability scanning |
| TDD Integration | ✅ 100% | Automated testing every 60s |
| Modern UI | ✅ 100% | Dear PyGui responsive dashboard |
| Logging System | ✅ 100% | 10 independent log files |

### Puntos Fuertes del Sistema

1. **Arquitectura Modular**: Sistema de plugins altamente extensible
2. **Detección Multi-Capa**: Combina múltiples técnicas de detección
3. **Machine Learning**: Modelos ONNX con alta precisión
4. **Testing Automático**: TDD + IAST integrados
5. **Interfaz Moderna**: Dear PyGui con dashboard responsivo
6. **Logging Avanzado**: Sistema robusto con 10 logs independientes
7. **Patrones de Diseño**: Implementación profesional de patrones GoF
8. **Documentación**: Más de 60 archivos MD con documentación completa

### Casos de Uso Principales

1. **Protección en Tiempo Real**: Monitoreo continuo del sistema
2. **Análisis Forense**: Logs detallados para investigación
3. **Desarrollo de Plugins**: Framework extensible para nuevos detectores
4. **Investigación de Seguridad**: IAST y ML para análisis avanzado
5. **Educación**: Proyecto académico con amplia documentación

---

## 🎯 Conclusión

El **Sistema Anti-Keylogger Unificado** es un sistema de seguridad profesional de arquitectura avanzada que implementa las mejores prácticas de ingeniería de software. Con su sistema modular de plugins, detección basada en Machine Learning, testing automático integrado y una interfaz moderna, representa un proyecto completo de seguridad informática.

El sistema está organizado en **7 carpetas principales**:
- **CONFIG**: Configuración centralizada
- **CORE**: Motor y gestión de plugins
- **PLUGINS**: Detectores, monitores y handlers
- **FRONTEND**: Interfaz Dear PyGui moderna
- **LOGS**: Sistema de logging avanzado
- **MODELS**: Modelos de Machine Learning
- **TESTS**: Suite TDD/IAST completa

Cada componente está **bien documentado**, **probado** y sigue **patrones de diseño** reconocidos, lo que hace que el sistema sea mantenible, extensible y profesional.

---

**Documento generado**: 2025-11-19  
**Versión del Sistema**: 1.0.0  
**Autor**: Sistema Anti-Keylogger Unificado Team
