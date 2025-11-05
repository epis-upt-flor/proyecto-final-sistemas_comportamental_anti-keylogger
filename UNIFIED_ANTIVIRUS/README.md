# 🛡️ Sistema Anti-Keylogger Unificado

## Descripción General

Sistema avanzado de detección y prevención de keyloggers desarrollado en Python. Implementa múltiples capas de detección utilizando análisis de comportamiento, machine learning, monitoreo de red y análisis heurístico para identificar y neutralizar amenazas de captura de teclado en tiempo real.

Este sistema antivirus modular utiliza una arquitectura basada en plugins con patrones de diseño de software avanzados (Facade, Observer, Strategy, Template Method, Factory) para proporcionar protección integral contra keyloggers y spyware.

## 🎯 Características Principales

- **Detección Multi-Capa**: Combina análisis de comportamiento, ML y monitoreo de red
- **Arquitectura Modular**: Sistema de plugins extensible y escalable
- **Machine Learning**: Modelos ONNX entrenados para detección de keyloggers
- **Monitoreo en Tiempo Real**: Vigilancia continua de procesos, archivos y red
- **Interfaz Gráfica Avanzada**: UI profesional con tkinter para gestión visual
- **Sistema de Cuarentena**: Aislamiento seguro de archivos maliciosos
- **Gestión de Alertas**: Sistema completo de notificaciones y logging
- **Event Bus**: Comunicación desacoplada entre componentes

## 📁 Estructura del Proyecto

```
UNIFIED_ANTIVIRUS/
│
├── launcher.py                      # Punto de entrada principal (backend only)
├── professional_ui_robust.py        # Interfaz gráfica profesional con tkinter
├── simple_backend.py                # Ejecutor directo del backend original
├── register_plugins.py              # Sistema de auto-registro de plugins
├── install_dependencies.py          # Instalador de dependencias Python
│
├── core/                            # Núcleo del sistema
│   ├── __init__.py
│   ├── engine.py                    # Motor principal (Facade Pattern)
│   ├── plugin_manager.py            # Gestor de plugins (Factory Pattern)
│   ├── event_bus.py                 # Sistema de eventos (Observer Pattern)
│   ├── base_plugin.py               # Clase base para plugins (Template Method)
│   ├── interfaces.py                # Interfaces de plugins
│   └── plugin_registry.py           # Registro centralizado de plugins
│
├── plugins/                         # Sistema de plugins modular
│   ├── detectors/                   # Plugins de detección
│   │   ├── behavior_detector/       # Detección por comportamiento
│   │   ├── keylogger_detector/      # Detector especializado de keyloggers
│   │   ├── ml_detector/             # Detección con Machine Learning
│   │   └── network_detector/        # Análisis de tráfico de red
│   │
│   ├── monitors/                    # Plugins de monitoreo
│   │   ├── file_monitor/            # Monitoreo del sistema de archivos
│   │   ├── network_monitor/         # Monitoreo de conexiones de red
│   │   └── process_monitor/         # Monitoreo de procesos
│   │
│   └── handlers/                    # Plugins de manejo de eventos
│       ├── alert_manager/           # Gestor de alertas
│       ├── logger_handler/          # Handler de logging estructurado
│       └── quarantine_handler/      # Gestor de cuarentena
│
├── config/                          # Archivos de configuración
│   ├── unified_config.toml          # Configuración principal del sistema
│   ├── alerts_config.json           # Configuración de alertas
│   ├── ml_config.json               # Configuración de modelos ML
│   ├── plugins_config.json          # Configuración de plugins
│   ├── security_config.json         # Configuración de seguridad
│   ├── whitelist.json               # Lista blanca de procesos
│   └── safe_profiles.json           # Perfiles de comportamiento seguro
│
├── models/                          # Modelos de Machine Learning
│   ├── keylogger_model_large_*.onnx # Modelo ONNX principal
│   ├── modelo_keylogger_*.onnx      # Modelo alternativo
│   ├── label_classes.json           # Clases de etiquetas
│   └── onnx_metadata_*.json         # Metadatos de modelos
│
├── utils/                           # Utilidades del sistema
│   ├── logger.py                    # Sistema de logging avanzado
│   ├── security_utils.py            # Utilidades de seguridad
│   ├── system_utils.py              # Utilidades del sistema
│   └── file_utils.py                # Utilidades de archivos
│
├── logs/                            # Directorio de logs
├── threat_intel/                    # Inteligencia de amenazas
│   ├── malicious_ips.txt            # IPs maliciosas conocidas
│   └── domains.txt                  # Dominios sospechosos
│
└── doc/                             # Documentación
    └── articulo_keylogger_antivirus.tex
```

## 🏗️ Arquitectura del Sistema

### Patrones de Diseño Implementados

1. **Facade Pattern** (`engine.py`): Simplifica la interfaz compleja del sistema
2. **Observer Pattern** (`event_bus.py`): Comunicación desacoplada entre componentes
3. **Factory Pattern** (`plugin_manager.py`): Creación dinámica de plugins
4. **Template Method** (`base_plugin.py`): Ciclo de vida común para plugins
5. **Strategy Pattern** (detectores): Diferentes estrategias de detección

### Flujo de Funcionamiento

```
1. Launcher inicia el UnifiedAntivirusEngine
2. Engine descubre y carga plugins automáticamente
3. Plugins se suscriben al Event Bus
4. Monitores capturan eventos del sistema
5. Detectores analizan los eventos
6. Handlers gestionan alertas y acciones
7. UI refleja el estado en tiempo real
```

## 🚀 Uso del Sistema

### Instalación de Dependencias

```bash
# Opción 1: Script automático
python install_dependencies.py

# Opción 2: Manual
pip install -r xd/requirements.txt
```

### Ejecución del Sistema

#### Modo Backend (Sin UI)

```bash
# Iniciar con todos los plugins
python launcher.py

# Solo detectores
python launcher.py --detectors-only

# Categorías específicas
python launcher.py --categories detectors monitors

# Modo debug
python launcher.py --debug
```

#### Modo UI (Interfaz Gráfica)

```bash
# Interfaz gráfica profesional
python professional_ui_robust.py
```

### Configuración

Editar `config/unified_config.toml` para ajustar:
- Umbrales de detección
- Plugins habilitados
- Configuración de ML
- Niveles de logging
- Comportamiento del sistema

## 📋 Archivos Principales

### `launcher.py`
**Propósito**: Punto de entrada principal del sistema (backend sin UI)

**Funcionalidad**:
- Parsea argumentos de línea de comandos
- Inicializa el UnifiedAntivirusEngine
- Gestiona el ciclo de vida del sistema
- Maneja señales de sistema (CTRL+C)
- Mantiene el sistema ejecutándose

**Descripción Técnica**:
Implementa el patrón de entrada única para el sistema. Utiliza `argparse` para configuración flexible por línea de comandos. Inicia el motor principal y mantiene el programa en ejecución hasta recibir señal de terminación.

### `professional_ui_robust.py`
**Propósito**: Interfaz gráfica profesional para el antivirus

**Funcionalidad**:
- Dashboard con métricas en tiempo real
- Visualización de amenazas detectadas
- Panel de configuración de plugins
- Sistema de logs estructurado
- Gráficas de rendimiento del sistema
- Control de protección (iniciar/detener)

**Descripción Técnica**:
Aplicación tkinter robusta con arquitectura MVC. Utiliza threading para actualización asíncrona de UI sin bloqueos. Implementa sistema de colas (`queue.Queue`) para comunicación thread-safe con el motor. Optimizada para manejar grandes volúmenes de datos sin degradación de rendimiento.

**Características técnicas**:
- Sistema de agregación de amenazas para evitar spam
- Buffer circular (deque) para logs con límite de memoria
- Actualización incremental de UI (cada 5 segundos)
- Caché de amenazas para rendimiento
- Manejo robusto de errores y excepciones

### `register_plugins.py`
**Propósito**: Sistema de auto-registro de plugins

**Funcionalidad**:
- Descubre plugins automáticamente
- Registra plugins en el PluginRegistry
- Valida configuraciones de plugins
- Maneja errores de importación gracefully

**Descripción Técnica**:
Utiliza introspección de Python para descubrir clases de plugins. Implementa patrón Registry centralizado. Proporciona capa de abstracción para registro dinámico sin modificar código del motor.

### `simple_backend.py`
**Propósito**: Ejecutor directo del backend original (ANTIVIRUS_PRODUCTION)

**Funcionalidad**:
- Ejecuta el sistema antivirus legacy
- Proporciona compatibilidad hacia atrás
- Gestiona cambio de directorio y ejecución

**Descripción Técnica**:
Script de compatibilidad que ejecuta `antivirus_launcher.py` del sistema ANTIVIRUS_PRODUCTION usando subprocess. Cambia el working directory temporalmente para ejecución correcta.

### `install_dependencies.py`
**Propósito**: Instalador automático de dependencias

**Funcionalidad**:
- Verifica Python instalado
- Instala pip si no existe
- Instala todas las dependencias necesarias
- Valida instalación correcta

**Descripción Técnica**:
Script de bootstrapping que utiliza subprocess para ejecutar pip. Maneja diferentes sistemas operativos y configuraciones de Python. Proporciona feedback detallado del proceso de instalación.

## 🔧 Dependencias Principales

- **psutil**: Monitoreo de procesos y sistema
- **onnxruntime**: Ejecución de modelos ML
- **watchdog**: Monitoreo de archivos
- **pywin32**: APIs de Windows
- **tkinter**: Interfaz gráfica (incluido en Python)
- **toml**: Parseo de configuración
- **numpy**: Operaciones numéricas para ML

## 📊 Métricas y Monitoreo

El sistema recopila métricas en tiempo real:
- Amenazas detectadas totales
- Amenazas únicas identificadas
- Plugins activos
- Uso de recursos (CPU, RAM)
- Tiempo de actividad del sistema
- Escaneos completados

## 🔐 Seguridad

### Características de Seguridad

- **Whitelisting**: Lista blanca de procesos seguros
- **Cuarentena**: Aislamiento seguro de archivos maliciosos
- **Logging estructurado**: Auditoría completa de eventos
- **Validación de entrada**: Sanitización de datos
- **Cifrado**: Soporte para cifrado de archivos en cuarentena

### Análisis de Amenazas

El sistema detecta:
- Keyloggers basados en hooks de Windows
- Captura de pantalla sospechosa
- Inyección de código
- Conexiones de red maliciosas
- Patrones de archivos de log
- Comportamiento stealth
- APIs sospechosas de Windows

## 🧪 Testing

El sistema incluye tests para:
- Plugins individuales
- Detectores de amenazas
- Monitores del sistema
- Motor principal

Ejecutar tests:
```bash
python -m pytest plugins/*/test_*.py
```

## 📝 Logging

Sistema de logging multinivel:
- **DEBUG**: Información detallada de desarrollo
- **INFO**: Eventos normales del sistema
- **WARNING**: Eventos sospechosos
- **ERROR**: Errores recuperables
- **CRITICAL**: Errores críticos

Logs guardados en `logs/`:
- `antivirus.log`: Log principal
- `launcher.log`: Log del launcher
- `[plugin_name].log`: Logs por plugin

## 🤝 Contribución

Este es un proyecto académico del curso de Sistemas Comportamentales.

## 📄 Licencia

Proyecto académico - Universidad Privada de Tacna

## 👥 Autores

Estudiantes del curso de Sistemas Comportamentales - UPT

---

**Nota**: Este sistema está diseñado para propósitos educativos y de investigación. Para uso en producción, se recomienda realizar auditorías de seguridad adicionales y pruebas exhaustivas.
