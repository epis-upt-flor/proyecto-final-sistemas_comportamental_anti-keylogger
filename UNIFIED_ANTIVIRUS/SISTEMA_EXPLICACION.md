
# Explicación del Sistema Antivirus Unificado

Este documento detalla el funcionamiento, la arquitectura y los objetivos del Sistema Antivirus Unificado, respondiendo a preguntas clave sobre su diseño e implementación.

## ¿De qué trata tu sistema?

### Respuesta Narrativa

El sistema es una plataforma de ciberseguridad modular y extensible diseñada para proteger sistemas informáticos contra una variedad de amenazas. Su núcleo es un motor de antivirus que puede ser ampliado con diferentes plugins para detectar y mitigar amenazas específicas, como malware, keyloggers o comportamientos anómalos en la red.

### Respuesta Muestral

El sistema se basa en un `UnifiedAntivirusEngine` que orquesta una serie de plugins. Como se ve en el diagrama de arquitectura, el `Core` interactúa con los `Plugins` y las `Configs`.

```python
# core/engine.py
class UnifiedAntivirusEngine:
    def __init__(self, config_path):
        # ... inicialización ...
        self.plugin_manager = PluginManager(self.config)
        self.event_bus = EventBus()
        # ...
```

## ¿Qué hace?

### Respuesta Narrativa

El sistema monitoriza continuamente el sistema en busca de actividades sospechosas. Utiliza una combinación de análisis basados en detección de comportamiento y modelos de machine learning para identificar amenazas. Cuando se detecta una amenaza, el sistema puede tomar varias acciones, como poner en cuarentena archivos, alertar al usuario o registrar el evento para un análisis posterior.

### Respuesta Muestral

El `DetectorEngine` es el componente central que ejecuta los análisis. Los plugins, como el `KeyloggerDetector`, se registran en el motor y son invocados para analizar datos o eventos del sistema.

```python
# plugins/detectors/keylogger_detector.py
class KeyloggerDetector(BasePlugin):
    def analyze(self, data):
        # Lógica para detectar keyloggers
        prediction = self.model.predict(data)
        if prediction == "keylogger":
            self.event_bus.publish("keylogger_detected", {"details": ...})
```

## ¿Cómo lo hace?

### Respuesta Narrativa

El sistema se inicia cargando una configuración central (`unified_config.toml`) que define qué plugins están activos y cómo deben comportarse. El `PluginManager` carga dinámicamente estos plugins. El `EventBus` permite la comunicación entre los diferentes componentes del sistema de forma desacoplada. Por ejemplo, un plugin de monitorización puede publicar un evento de "archivo nuevo creado", y los plugins de detección pueden suscribirse a este evento para analizar el archivo.

### Respuesta Muestral

El flujo comienza en el `UnifiedAntivirusEngine`, que inicializa el `PluginManager`. El `PluginManager` lee la configuración de `plugins_config.json` para saber qué plugins cargar.

```json
// config/plugins_config.json
{
    "detectors": [
        {"name": "KeyloggerDetector", "enabled": true},
        {"name": "BehaviorDetector", "enabled": true}
    ],
    "handlers": [
        {"name": "QuarantineHandler", "enabled": true}
    ]
}
```

El `PluginRegistry` mantiene un registro de todos los plugins disponibles, y el `PluginManager` los instancia y los gestiona.

## ¿Cuál es el objetivo o los objetivos?

### Respuesta Narrativa

Los objetivos principales son:
1.  **Modularidad y Extensibilidad:** Permitir que nuevas capacidades de detección se añadan fácilmente sin modificar el núcleo del sistema.
2.  **Flexibilidad:** Permitir a los usuarios configurar el nivel de seguridad y los tipos de análisis que desean ejecutar.
3.  **Rendimiento:** Ser eficiente en el uso de recursos para no impactar negativamente el rendimiento del sistema anfitrión.
4.  **Precisión:** Minimizar los falsos positivos y negativos en la detección de amenazas.

### Respuesta Muestral

La arquitectura de plugins es la prueba principal del objetivo de modularidad. Cada plugin es una clase que hereda de `BasePlugin` e implementa la interfaz requerida.

```python
# core/base_plugin.py
class BasePlugin:
    def __init__(self, config, event_bus):
        self.config = config
        self.event_bus = event_bus

    def setup(self):
        pass

    def teardown(self):
        pass
```

## ¿Se cumplen los objetivos?

### Respuesta Narrativa

Sí, los objetivos se cumplen en gran medida. La arquitectura basada en plugins y la configuración centralizada demuestran la modularidad y flexibilidad del sistema. El uso de un `ResourceMonitor` (como se ve en `core/resource_monitor.py`) ayuda a gestionar el consumo de recursos, abordando el objetivo de rendimiento. La precisión se busca a través de modelos de machine learning y la capacidad de actualizar las "firmas" de amenazas.

### Respuesta Muestral

El `PluginManager` y el `PluginRegistry` son la prueba de que el sistema es modular. La existencia de varios archivos de configuración (`security_config.json`, `ml_config.json`, etc.) muestra la flexibilidad. El directorio `tests` con `IntegrationTests` y `TDD_Suites` confirma que la funcionalidad se valida continuamente.

## ¿Cuál es la problemática?

### Respuesta Narrativa

La problemática que aborda el sistema es el panorama de amenazas cibernéticas en constante evolución. Los antivirus tradicionales basados en firmas son insuficientes para detectar amenazas nuevas y desconocidas (ataques de día cero). Este sistema busca solucionar esto mediante un enfoque de defensa en profundidad, combinando múltiples técnicas de detección y permitiendo una rápida adaptación a nuevas amenazas a través de su arquitectura de plugins.

### Respuesta Muestral

La existencia de un `BehaviorDetector` y un `KeyloggerDetector` que utiliza un modelo de machine learning (`ONNX Model`) son una respuesta directa a la problemática. Estos componentes no dependen de firmas estáticas, sino que analizan comportamientos y patrones para detectar amenazas.

```python
# plugins/detectors/behavior_detector.py
class BehaviorDetector(BasePlugin):
    def analyze_process_behavior(self, process_events):
        # Analiza la secuencia de eventos de un proceso
        # para detectar comportamientos maliciosos (e.g., ransomware).
        ...
```

## ¿Qué tecnologías usa?

### Respuesta Narrativa

El sistema está construido principalmente en **Python**. Utiliza **ONNX (Open Neural Network Exchange)** para ejecutar modelos de machine learning de forma portable. La configuración se gestiona a través de archivos **JSON** y **TOML**. La arquitectura se define y visualiza usando **PlantUML**.

### Respuesta Muestral

-   **Python:** Todo el código fuente en los directorios `core`, `plugins`, `utils`, etc.
-   **ONNX:** Los modelos en el directorio `models/`, como `keylogger_model_large_20250918_112840.onnx`.
-   **JSON/TOML:** Los archivos de configuración en `config/`, como `unified_config.toml` y `plugins_config.json`.
-   **PlantUML:** Los diagramas de arquitectura en `doc/`, como `architecture.puml`.

## ¿Cómo sabes que tu programa funciona?

### Respuesta Narrativa

La confianza en el funcionamiento del programa se basa en un conjunto exhaustivo de pruebas. El sistema incluye pruebas unitarias, pruebas de integración y pruebas de seguridad. Las pruebas de TDD (Test-Driven Development) aseguran que cada nueva característica se desarrolla con sus pruebas correspondientes. Las pruebas de seguridad (AST) validan la robustez del sistema contra ataques.

### Respuesta Muestral

El directorio `tests/` contiene las suites de pruebas.
-   `TDD_Suites`: Pruebas desarrolladas siguiendo la metodología TDD.
-   `IntegrationTests`: Pruebas que verifican la interacción correcta entre los diferentes componentes (motor, plugins, configuración).
-   `AST_Security_Tests`: Pruebas de seguridad de análisis estático de código.

```
tests/
├── __init__.py
├── conftest.py
├── integration/
│   ├── test_engine_integration.py
│   └── test_plugin_loading.py
├── tdd/
│   ├── test_keylogger_detector_tdd.py
│   └── test_quarantine_handler_tdd.py
└── security/
    └── test_ast_vulnerabilities.py
```

## ¿Cómo funciona el machine learning?

### Respuesta Narrativa

El machine learning se utiliza para la detección de amenazas basadas en patrones complejos que son difíciles de describir con reglas manuales. Por ejemplo, para detectar un keylogger, se entrena un modelo con datos de comportamiento normal y de comportamiento de keyloggers. Este modelo, una vez entrenado, se exporta al formato ONNX. El `KeyloggerDetector` carga este modelo y lo utiliza para clasificar la actividad del sistema en tiempo real.

### Respuesta Muestral

1.  **Modelo:** El modelo se encuentra en `models/modelo_keylogger_from_datos.onnx`. Los metadatos y las clases se describen en `onnx_metadata_large_20250918_112840.json` y `label_classes.json`.

2.  **Carga del modelo:** El plugin de detección carga el modelo ONNX usando una librería como `onnxruntime`.

    ```python
    # plugins/detectors/keylogger_detector.py
    import onnxruntime as rt

    class KeyloggerDetector(BasePlugin):
        def setup(self):
            self.model_path = self.config.get("model_path")
            self.session = rt.InferenceSession(self.model_path)
            self.input_name = self.session.get_inputs()[0].name
            self.label_name = self.session.get_outputs()[0].name

        def analyze(self, data):
            # Preprocesar 'data' para que coincida con la entrada del modelo
            input_data = preprocess(data)
            res = self.session.run([self.label_name], {self.input_name: input_data})
            # ... lógica de detección ...
    ```

## Flujo de Operación y Opciones del Usuario

### Respuesta Narrativa

Al iniciar, el `launcher.py` o `production_launcher.py` carga el `UnifiedAntivirusEngine`. El motor lee el archivo `unified_config.toml` para obtener la configuración global y luego carga los plugins especificados en `plugins_config.json`. Los plugins de monitorización empiezan a recopilar datos del sistema (ej. eventos de archivos, conexiones de red). Estos datos se envían a los plugins de detección a través del `EventBus`.

Si un detector identifica una amenaza, publica un evento de "amenaza detectada". Los plugins de manejo de amenazas (`handlers`), como el `QuarantineHandler` o el `AlertManager`, reaccionan a este evento. El `QuarantineHandler` moverá el archivo malicioso a una zona segura, y el `AlertManager` notificará al usuario a través de la interfaz de usuario (`frontend/main.py`).

El usuario puede interactuar con el sistema a través de la interfaz de usuario para:
-   Ver las alertas de seguridad.
-   Gestionar los archivos en cuarentena.
-   Iniciar un análisis manual.
-   Configurar el comportamiento del antivirus editando los perfiles de seguridad en `safe_profiles.json` o la lista blanca en `whitelist.json`.

El sistema se cierra de forma segura a través del método `shutdown` del motor, que a su vez llama al método `teardown` de cada plugin para liberar recursos.
