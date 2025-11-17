# 🎯 Carpeta `/core` - Núcleo del Sistema

## Descripción General

La carpeta `core/` contiene el núcleo arquitectónico del Sistema Anti-Keylogger Unificado. Implementa los componentes fundamentales que coordinan todos los plugins, gestionan la comunicación entre módulos y definen la estructura base del sistema.

Esta carpeta es el **corazón del sistema**, implementando patrones de diseño de software avanzados para crear una arquitectura robusta, extensible y mantenible.

## 🏗️ Arquitectura y Patrones de Diseño

El núcleo implementa los siguientes patrones:

- **Facade Pattern** → `engine.py`
- **Factory Pattern** → `plugin_manager.py`
- **Observer Pattern** → `event_bus.py`
- **Template Method Pattern** → `base_plugin.py`
- **Strategy Pattern** → `interfaces.py`
- **Registry Pattern** → `plugin_registry.py`
- **Singleton Pattern** → `plugin_registry.py`

## 📋 Archivos del Módulo Core

### `__init__.py`
**Propósito**: Inicialización del paquete core y exports públicos

**Funcionalidad**:
- Expone las clases principales del core
- Define la API pública del módulo
- Simplifica imports para otros módulos

**Descripción Técnica**:
Archivo de inicialización de Python que convierte el directorio en un paquete importable. Define `__all__` para controlar qué se exporta con `from core import *`. Centraliza la exposición de componentes principales como `UnifiedAntivirusEngine`, `PluginManager`, `event_bus`, etc.

---

### `engine.py` 🚀
**Propósito**: Motor principal del sistema (Facade Pattern)

**Funcionalidad**:
- Coordina todos los componentes del sistema
- Proporciona interfaz simplificada para operaciones complejas
- Gestiona el ciclo de vida completo del antivirus
- Inicia/detiene plugins de manera ordenada
- Maneja señales del sistema (SIGINT, SIGTERM)
- Publica eventos del sistema
- Mantiene estadísticas globales

**Descripción Técnica**:

El `UnifiedAntivirusEngine` implementa el **Facade Pattern** para ocultar la complejidad interna del sistema detrás de una interfaz simple y unificada.

**Componentes principales**:

1. **Inicialización**:
   ```python
   __init__(config_path: str)
   ```
   - Carga configuración desde TOML
   - Inicializa `PluginManager`
   - Configura manejadores de señales
   - Inicializa diccionario de estadísticas

2. **Métodos Facade**:
   ```python
   start_system(plugin_categories: List[str])
   ```
   - Descubre y carga plugins
   - Configura event handlers del sistema
   - Activa plugins por categoría
   - Inicia monitoreo de estadísticas
   - Publica evento `system_started`

   ```python
   shutdown_system()
   ```
   - Detiene monitoreo de estadísticas
   - Desactiva todos los plugins gracefully
   - Limpia event bus
   - Publica evento `system_shutdown_started`

   ```python
   restart_system()
   ```
   - Ejecuta shutdown seguido de start
   - Pausa entre operaciones para limpieza

3. **Control de Plugins**:
   ```python
   activate_plugin(plugin_name: str)
   deactivate_plugin(plugin_name: str)
   reload_plugin(plugin_name: str)
   get_plugin_status(plugin_name: str)
   ```
   - Delegación al PluginManager
   - Validaciones adicionales
   - Logging de operaciones

4. **Gestión de Eventos**:
   ```python
   _setup_system_event_handlers()
   _handle_threat_detected(event: Event)
   _handle_system_error(event: Event)
   ```
   - Suscripción a eventos críticos
   - Actualización de estadísticas
   - Logging estructurado

5. **Monitoreo de Estadísticas**:
   ```python
   _start_stats_monitoring()
   _stats_monitoring_loop()
   ```
   - Thread daemon para estadísticas periódicas
   - Actualización de uptime
   - Publicación de métricas del sistema

**Flujo de ejecución**:
```
1. __init__() → Configura componentes
2. start_system() → Inicializa plugins
3. [Sistema en ejecución]
4. shutdown_system() → Limpieza ordenada
```

**Características técnicas**:
- Thread-safe mediante locks
- Manejo robusto de excepciones
- Logging detallado de operaciones
- Shutdown graceful con timeouts
- Singleton de facto (una instancia por proceso)

---

### `plugin_manager.py` 🎛️
**Propósito**: Gestor de plugins (Abstract Factory + Facade)

**Funcionalidad**:
- Descubre plugins automáticamente en directorios
- Crea instancias de plugins (Factory Method)
- Gestiona el ciclo de vida de plugins
- Mantiene registro de plugins activos
- Conecta plugins al Event Bus
- Maneja threading para plugins asíncronos
- Controla dependencias entre plugins

**Descripción Técnica**:

El `PluginManager` combina **Abstract Factory Pattern** (para crear familias de plugins) con **Facade Pattern** (para simplificar la gestión compleja de plugins).

**Componentes principales**:

1. **Factory Methods**:
   ```python
   discover_and_load_plugins() -> bool
   ```
   - Escanea directorio `plugins/`
   - Descubre plugins por categoría
   - Registra en PluginRegistry
   - Valida configuraciones

   ```python
   create_plugin_family(category: str) -> Dict[str, BasePlugin]
   ```
   - Crea familia completa de plugins (ej: todos los detectores)
   - Factory Method para categorías específicas
   - Retorna diccionario de instancias

   ```python
   create_plugin(plugin_name: str, **kwargs) -> Optional[BasePlugin]
   ```
   - Factory Method principal
   - Crea instancia individual de plugin
   - Conecta al Event Bus automáticamente
   - Maneja errores de creación

2. **Ciclo de Vida de Plugins** (Template Method):
   ```python
   activate_plugin(plugin_name: str) -> bool
   ```
   - Verifica si ya está activo
   - Crea instancia del plugin
   - Ejecuta `plugin.activate()`
   - Inicia thread si es necesario
   - Registra como activo
   - Publica evento `plugin_activated`

   ```python
   deactivate_plugin(plugin_name: str) -> bool
   ```
   - Ejecuta `plugin.deactivate()`
   - Detiene thread si existe
   - Remueve del registro de activos
   - Publica evento `plugin_deactivated`

3. **Activación por Categoría**:
   ```python
   activate_category(category: str) -> int
   ```
   - Activa todos los plugins de una categoría
   - Maneja errores individuales sin fallar el batch
   - Retorna cantidad activada

4. **Threading para Plugins**:
   ```python
   _start_plugin_thread(plugin: BasePlugin)
   ```
   - Crea thread daemon para plugins que lo requieren
   - Manejo de excepciones en threads
   - Registro de threads activos

5. **Gestión de Estado**:
   ```python
   get_active_plugins() -> List[str]
   is_plugin_active(plugin_name: str) -> bool
   get_plugin_info(plugin_name: str) -> Dict
   get_categories() -> List[str]
   ```
   - Consultas de estado del sistema
   - Información detallada de plugins

**Características técnicas**:
- **Thread-safe**: Usa `threading.RLock()` para operaciones concurrentes
- **Manejo robusto de errores**: Fallos individuales no afectan el sistema
- **Lazy loading**: Plugins solo se cargan cuando se activan
- **Dependency injection**: Event Bus se inyecta en plugins
- **Observer integration**: Plugins se suscriben automáticamente a eventos

---

### `event_bus.py` 🚌
**Propósito**: Sistema de comunicación desacoplada (Observer Pattern)

**Funcionalidad**:
- Implementa patrón Publisher-Subscriber
- Permite comunicación entre plugins sin acoplamiento
- Mantiene historial de eventos
- Notificación asíncrona a suscriptores
- Thread-safe para uso concurrente

**Descripción Técnica**:

El `EventBus` implementa el **Observer Pattern** para permitir comunicación desacoplada entre componentes del sistema.

**Clases principales**:

#### 1. `Event`
Encapsula información de un evento (Command Pattern):

```python
class Event:
    event_type: str      # Tipo de evento
    data: Dict[str, Any] # Datos del evento
    source: str          # Plugin/componente origen
    timestamp: datetime  # Momento de creación
    event_id: str        # ID único
```

Métodos:
- `to_dict()`: Serialización para logging/persistencia
- `__str__()`: Representación legible

#### 2. `EventBus`
Sistema principal de eventos:

**Atributos**:
```python
_subscribers: Dict[str, List[Callable]]  # event_type -> [callbacks]
_lock: threading.RLock()                  # Thread safety
_event_history: List[Event]               # Historial limitado
_max_history: int = 1000                  # Límite de eventos
```

**Métodos principales**:

1. **Suscripción**:
   ```python
   subscribe(event_type: str, callback: Callable, 
            subscriber_name: str) -> bool
   ```
   - Registra callback para tipo de evento
   - Múltiples suscriptores por evento
   - Thread-safe con lock

2. **Publicación**:
   ```python
   publish(event_type: str, data: Dict, source: str) -> bool
   ```
   - Crea objeto Event
   - Guarda en historial
   - Notifica asíncronamente a suscriptores
   - No bloquea al publisher

3. **Notificación Asíncrona**:
   ```python
   _notify_subscribers(event: Event, subscribers: List[Callable])
   ```
   - Ejecuta en thread separado
   - Llama cada callback con manejo de errores
   - Los fallos en un suscriptor no afectan otros

4. **Gestión de Historial**:
   ```python
   get_recent_events(count: int, event_type: str) -> List[Event]
   get_events_by_source(source: str) -> List[Event]
   clear_history()
   ```
   - Consultas de eventos pasados
   - Filtrado por tipo o fuente
   - Limpieza de historial

**Tipos de eventos comunes**:
- `threat_detected`: Amenaza detectada
- `plugin_activated`: Plugin activado
- `plugin_deactivated`: Plugin desactivado
- `system_started`: Sistema iniciado
- `system_shutdown_started`: Shutdown iniciado
- `scan_completed`: Escaneo completado
- `file_quarantined`: Archivo en cuarentena
- `alert_triggered`: Alerta generada

**Características técnicas**:
- **Asíncrono**: Notificaciones no bloquean publisher
- **Thread-safe**: RLock para operaciones concurrentes
- **Resiliente**: Errores en suscriptores aislados
- **Observable**: Historial para auditoría
- **Escalable**: Manejo eficiente de múltiples suscriptores

**Flujo de eventos típico**:
```
Monitor detecta actividad → Publica evento
↓
Event Bus notifica suscriptores
↓
Detectores analizan → Publican threat_detected
↓
Handlers responden → Alert, Quarantine, Log
↓
UI actualiza → Muestra información
```

---

### `base_plugin.py` 📦
**Propósito**: Clase base para todos los plugins (Template Method Pattern)

**Funcionalidad**:
- Define el ciclo de vida estándar de plugins
- Proporciona funcionalidad común (logging, config)
- Métodos abstractos para implementación específica
- Template Method para activación/desactivación

**Descripción Técnica**:

La clase `BasePlugin` implementa el **Template Method Pattern** definiendo el algoritmo común para todos los plugins mientras permite personalización de pasos específicos.

**Estructura de la clase**:

```python
class BasePlugin(ABC):
    plugin_name: str
    plugin_path: Path
    config: Dict
    is_running: bool
    logger: logging.Logger
```

**Template Method Principal**:

```python
def activate(self) -> bool:
    """Template method que define algoritmo completo"""
    # Pasos comunes (implementados en BasePlugin)
    self.setup_logging()
    self.load_config()
    
    # Pasos específicos (abstractos - cada plugin implementa)
    if not self.initialize():
        return False
    if not self.start():
        return False
    
    self.is_running = True
    return True

def deactivate(self) -> bool:
    """Template method para desactivación"""
    if self.is_running:
        self.stop()     # Específico
    self.cleanup()      # Común
    self.is_running = False
    return True
```

**Métodos Comunes** (implementados en BasePlugin):

1. **`setup_logging()`**:
   - Configura logger específico del plugin
   - Crea archivo de log individual
   - Establece formato y handlers
   - Nivel de logging configurable

2. **`load_config()`**:
   - Carga `config.json` del directorio del plugin
   - Merge con configuración por defecto
   - Validación de configuración
   - Manejo de errores graceful

3. **`cleanup()`**:
   - Libera recursos del plugin
   - Cierra archivos y conexiones
   - Operaciones de limpieza comunes

**Métodos Abstractos** (cada plugin debe implementar):

1. **`initialize(self) -> bool`**:
   - Inicialización específica del plugin
   - Carga de recursos (modelos ML, firmas, etc.)
   - Validación de dependencias
   - Retorna True si inicializa correctamente

2. **`start(self) -> bool`**:
   - Inicia la funcionalidad principal del plugin
   - Comienza monitoreo/detección
   - Inicia threads si es necesario
   - Retorna True si inicia correctamente

3. **`stop(self)`**:
   - Detiene la funcionalidad del plugin
   - Para threads y procesos
   - Guarda estado si es necesario

**Métodos Adicionales**:

```python
def get_status(self) -> Dict[str, Any]:
    """Estado actual del plugin"""
    return {
        'name': self.plugin_name,
        'running': self.is_running,
        'config': self.config
    }

def reload_config(self) -> bool:
    """Recarga configuración sin reiniciar"""
    self.load_config()
    return True
```

**Características técnicas**:
- **Abstracción**: Define contrato para todos los plugins
- **Reutilización**: Código común compartido
- **Extensibilidad**: Fácil añadir nuevos plugins
- **Consistencia**: Comportamiento uniforme
- **Mantenibilidad**: Cambios centralizados

**Jerarquía de herencia**:
```
BasePlugin (abstract)
  ├── DetectorPlugin (detectores)
  ├── MonitorPlugin (monitores)
  └── HandlerPlugin (handlers)
```

---

### `interfaces.py` 🔌
**Propósito**: Definición de interfaces (Strategy Pattern)

**Funcionalidad**:
- Define contratos para diferentes tipos de plugins
- Permite intercambio de implementaciones
- Garantiza consistencia de API
- Facilita testing con mocks

**Descripción Técnica**:

El archivo `interfaces.py` define **interfaces abstractas** usando el **Strategy Pattern** para permitir diferentes estrategias intercambiables de detección, monitoreo y manejo de eventos.

**Interfaces Principales**:

#### 1. `DetectorInterface`
Para plugins de detección de amenazas:

```python
class DetectorInterface(ABC):
    @abstractmethod
    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analiza datos y retorna amenazas detectadas"""
        pass
    
    @abstractmethod
    def get_confidence_score(self) -> float:
        """Score de confianza de última detección (0.0-1.0)"""
        pass
    
    @abstractmethod
    def update_signatures(self) -> bool:
        """Actualiza firmas/patrones de detección"""
        pass
    
    @abstractmethod
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Estadísticas de rendimiento del detector"""
        pass
```

**Implementadores**: `MLDetectorPlugin`, `BehaviorDetectorPlugin`, `NetworkDetectorPlugin`, `KeyloggerDetector`

#### 2. `MonitorInterface`
Para plugins de monitoreo del sistema:

```python
class MonitorInterface(ABC):
    @abstractmethod
    def start_monitoring(self) -> bool:
        """Inicia monitoreo continuo"""
        pass
    
    @abstractmethod
    def stop_monitoring(self) -> bool:
        """Detiene monitoreo"""
        pass
    
    @abstractmethod
    def get_current_data(self) -> Dict[str, Any]:
        """Datos actuales del sistema monitoreado"""
        pass
    
    @abstractmethod
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Estadísticas del monitoreo"""
        pass
    
    @abstractmethod
    def set_monitoring_interval(self, interval: float) -> bool:
        """Configura intervalo de monitoreo"""
        pass
```

**Implementadores**: `ProcessMonitorPlugin`, `FileMonitorPlugin`, `NetworkMonitorPlugin`

#### 3. `HandlerInterface`
Para plugins que manejan eventos/amenazas:

```python
class HandlerInterface(ABC):
    @abstractmethod
    def handle_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Maneja un evento del sistema"""
        pass
    
    @abstractmethod
    def can_handle(self, event_type: str) -> bool:
        """Verifica si puede manejar un tipo de evento"""
        pass
    
    @abstractmethod
    def get_handler_priority(self) -> int:
        """Prioridad del handler (mayor = más prioritario)"""
        pass
    
    @abstractmethod
    def get_handler_statistics(self) -> Dict[str, Any]:
        """Estadísticas del handler"""
        pass
```

**Implementadores**: `AlertManagerPlugin`, `QuarantineHandlerPlugin`, `LoggerHandlerPlugin`

**Ventajas del Strategy Pattern**:
- **Intercambiabilidad**: Cambiar detectores sin modificar código
- **Testabilidad**: Fácil crear mocks
- **Extensibilidad**: Añadir nuevas estrategias
- **Separación de responsabilidades**: Cada interfaz define un rol claro

---

### `plugin_registry.py` 📚
**Propósito**: Registro centralizado de plugins (Registry + Singleton)

**Funcionalidad**:
- Registro dinámico de plugins
- Descubrimiento automático en directorios
- Búsqueda por nombre o categoría
- Creación de instancias (Factory Method)
- Gestión de metadatos de plugins

**Descripción Técnica**:

El `PluginRegistry` implementa **Registry Pattern** combinado con **Singleton Pattern** para proporcionar un punto único de acceso a todos los plugins del sistema.

**Características del Registry**:

```python
class PluginRegistry:
    _instance = None              # Singleton
    _plugins: Dict[str, Dict]     # Registro de plugins
    _categories = ['detectors', 'interfaces', 'monitors', 'handlers']
```

**Singleton Implementation**:
```python
def __new__(cls):
    if cls._instance is None:
        cls._instance = super().__new__(cls)
    return cls._instance
```

**Métodos principales**:

1. **Registro de Plugins**:
   ```python
   register_plugin(plugin_class: Type[BasePlugin], 
                   plugin_name: str = None,
                   category: str = None) -> bool
   ```
   - Valida que herede de BasePlugin
   - Infiere categoría automáticamente si no se especifica
   - Almacena metadatos del plugin
   - Permite sobrescritura con warning

2. **Inferencia de Categoría**:
   ```python
   _infer_category(plugin_class: Type[BasePlugin], name: str) -> str
   ```
   - **Estrategia 1**: Por nombre del módulo
   - **Estrategia 2**: Por nombre de la clase
   - **Estrategia 3**: Por palabras clave en el nombre
   - Retorna 'unknown' si no puede inferir

3. **Factory Method**:
   ```python
   create_plugin(plugin_name: str, plugin_path: str = None, 
                 **kwargs) -> Optional[BasePlugin]
   ```
   - Busca clase del plugin en registro
   - Crea instancia con parámetros
   - Retorna None si falla

4. **Descubrimiento Automático**:
   ```python
   discover_plugins(base_path: Path) -> int
   ```
   - Escanea directorio de plugins recursivamente
   - Importa módulos dinámicamente
   - Registra clases que heredan de BasePlugin
   - Retorna cantidad de plugins descubiertos

5. **Consultas**:
   ```python
   get_plugin_class(plugin_name: str) -> Optional[Type[BasePlugin]]
   get_plugins_by_category(category: str) -> List[str]
   get_all_plugins() -> List[str]
   get_plugin_info(plugin_name: str) -> Dict
   list_categories() -> List[str]
   ```

**Estructura de metadatos del plugin**:
```python
{
    'class': plugin_class,
    'name': 'plugin_name',
    'category': 'detectors',
    'module': 'plugins.detectors.ml_detector',
    'auto_discovered': True,
    'description': 'Plugin description'
}
```

**Características técnicas**:
- **Singleton**: Una sola instancia global
- **Lazy loading**: Plugins se cargan bajo demanda
- **Reflection**: Usa introspección de Python
- **Dynamic imports**: `importlib` para carga dinámica
- **Metadatos**: Información completa de cada plugin
- **Thread-safe**: Operaciones atómicas

**Flujo de descubrimiento**:
```
1. scan_directory(plugins/)
2. Para cada subdirectorio:
   3. Importar módulo
   4. Buscar clases que heredan BasePlugin
   5. Registrar con metadatos
   6. Categorizar automáticamente
```

---

## 🔄 Flujo de Comunicación entre Componentes

```
┌─────────────────────────────────────────────────────────┐
│                   UnifiedAntivirusEngine                 │
│                      (Facade Pattern)                    │
└─────────────────────┬───────────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  PluginManager   │      │    Event Bus     │
│  (Factory)       │◄────►│   (Observer)     │
└────────┬─────────┘      └────────┬─────────┘
         │                         │
         ▼                         │
┌──────────────────┐              │
│ PluginRegistry   │              │
│  (Registry +     │              │
│   Singleton)     │              │
└──────────────────┘              │
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
            ┌───────────────┐            ┌───────────────┐
            │   Monitors    │            │   Detectors   │
            │  (Strategy)   │───event───►│  (Strategy)   │
            └───────────────┘            └───────┬───────┘
                                                  │
                                                  │ event
                                                  ▼
                                          ┌───────────────┐
                                          │   Handlers    │
                                          │  (Strategy)   │
                                          └───────────────┘
```

## 🧪 Testing del Core

Para testear componentes del core:

```python
# Test del Event Bus
from core.event_bus import event_bus, Event

def test_callback(event: Event):
    print(f"Received: {event}")

event_bus.subscribe('test_event', test_callback, 'test_subscriber')
event_bus.publish('test_event', {'data': 'test'}, 'test_source')

# Test del PluginManager
from core.plugin_manager import PluginManager

pm = PluginManager()
pm.discover_and_load_plugins()
pm.activate_plugin('ml_detector')

# Test del Engine
from core import UnifiedAntivirusEngine

engine = UnifiedAntivirusEngine()
engine.start_system(['detectors'])
# ... operaciones ...
engine.shutdown_system()
```

## 💡 Mejores Prácticas

1. **Usar el Engine como punto de entrada**: No instanciar componentes directamente
2. **Publicar eventos en lugar de llamadas directas**: Desacoplar componentes
3. **Heredar de BasePlugin**: Todos los plugins deben heredar
4. **Implementar interfaces apropiadas**: Usar DetectorInterface, MonitorInterface, etc.
5. **Manejar errores gracefully**: No dejar que excepciones propaguen
6. **Logging estructurado**: Usar el logger del plugin con contexto
7. **Thread-safety**: Usar locks cuando sea necesario

## 🔐 Consideraciones de Seguridad

- El Event Bus no valida datos de eventos (responsabilidad de suscriptores)
- PluginManager ejecuta código de plugins (validar origen)
- BasePlugin carga configuración JSON (validar contenido)
- Engine tiene acceso a todo el sistema (permisos apropiados)

## 📊 Métricas del Core

El core recopila métricas:
- Plugins activos/inactivos
- Eventos publicados/procesados
- Tiempo de inicio/shutdown
- Errores en activación de plugins
- Latencia de eventos

## 🔗 **Enlaces Relacionados**

### Componentes del Sistema
- **[📋 README Principal](../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../plugins/README.md)** - Arquitectura de plugins que gestiona
- **[🔍 Detectores](../plugins/detectors/README.md)** - Plugins de detección coordinados
- **[👁️ Monitores](../plugins/monitors/README.md)** - Plugins de monitoreo gestionados
- **[🚨 Handlers](../plugins/handlers/README.md)** - Plugins de respuesta controlados
- **[⚙️ Configuración](../config/README.md)** - Sistema de configuración usado por engine
- **[📝 Logs](../logs/README.md)** - Sistema de logging coordinado
- **[🛠️ Utils](../utils/README.md)** - Utilidades usadas por componentes core

### Documentación Técnica
- **[🏗️ Interfaces](interfaces.py)** - Definiciones de interfaces del sistema
- **[🚀 Engine](engine.py)** - Motor principal y facade del sistema
- **[📡 Event Bus](event_bus.py)** - Sistema de comunicación entre plugins
- **[🔌 Plugin Manager](plugin_manager.py)** - Gestor de ciclo de vida de plugins
- **[📝 Base Plugin](base_plugin.py)** - Clase base para todos los plugins

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../README.md) - Motor Principal del Sistema**

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
