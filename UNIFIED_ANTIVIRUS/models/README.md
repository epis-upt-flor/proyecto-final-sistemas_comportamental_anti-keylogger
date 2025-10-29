# Models: El Cerebro de Inteligencia Artificial del Sistema

## ¿Qué es?

La carpeta `models` contiene los modelos de inteligencia artificial entrenados que constituyen el núcleo de la capacidad de detección automática del sistema anti-keylogger. Aquí residen los algoritmos de machine learning que han sido entrenados con miles de muestras de tráfico de red para distinguir entre comunicaciones benignas y actividad maliciosa característica de keyloggers.

Esta carpeta representa la materialización de todo el trabajo de ciencia de datos: desde la recolección y procesamiento de datasets hasta el entrenamiento y optimización de algoritmos, culminando en modelos listos para producción que pueden analizar tráfico de red en tiempo real y detectar patrones sutiles que serían imposibles de identificar mediante reglas tradicionales.

## ¿Qué hace?

**Detección Basada en Machine Learning:** Los modelos analizan 81 características específicas extraídas del tráfico de red para clasificar cada flujo de comunicación como "Benign" (benigno) o "Keylogger" (malicioso). Utilizan algoritmos de Random Forest entrenados en datasets reales para reconocer patrones complejos en características como duración de flujo, tamaños de paquetes, intervalos entre arribos, flags TCP, y estadísticas de comunicación.

**Clasificación Binaria Optimizada:** Implementan un sistema de clasificación binaria específicamente optimizado para detectar keyloggers, con clases claramente definidas que permiten al sistema tomar decisiones precisas sobre si una comunicación de red representa una amenaza o actividad normal del sistema.

**Inferencia en Múltiples Formatos:** Proporcionan capacidades de inferencia tanto en formato ONNX (optimizado para producción y interoperabilidad) como en formato pkl de sklearn (para compatibilidad y desarrollo), permitiendo flexibilidad en deployment y optimización de rendimiento según el entorno específico.

**Metadatos Estructurados:** Mantienen información detallada sobre las características del modelo, nombres de features, timestamps de entrenamiento, y configuraciones específicas que facilitan el debugging, monitoreo de rendimiento, y actualización de modelos.

## ¿Cómo lo hace?

**Arquitectura Random Forest:** Utilizan algoritmos de Random Forest que combinan múltiples árboles de decisión para crear predicciones robustas y resistentes al overfitting. Cada árbol vota sobre la clasificación final, y el ensemble proporciona tanto la predicción como un nivel de confianza basado en el consenso entre árboles.

**Procesamiento de 81 Características:** Analizan un conjunto específico de 81 características de red que incluyen estadísticas de flujo (duración, bytes totales, paquetes por segundo), características direccionales (forward vs backward packets), estadísticas de timing (intervalos entre arribos, tiempos activos e idle), y flags de protocolo (TCP flags, tamaños de ventana).

**Optimización ONNX:** Los modelos están disponibles en formato ONNX (Open Neural Network Exchange) que proporciona optimizaciones de rendimiento específicas para inferencia en producción, incluyendo optimizaciones de memoria, paralelización automática, y compatibilidad con diferentes hardware y frameworks.

**Versionado Temporal:** Cada modelo incluye timestamps específicos que indican cuándo fue entrenado y convertido, permitiendo rastrear la evolución del modelo, mantener múltiples versiones para A/B testing, y facilitar rollbacks si una nueva versión introduce problemas.

**Validación de Integridad:** Los metadatos incluyen información sobre el número esperado de características, nombres específicos de features, y configuraciones que permiten al sistema validar que está cargando el modelo correcto y que los datos de entrada tienen el formato esperado.

## ¿Para qué lo hace?

**Detección de Amenazas Desconocidas:** A diferencia de los sistemas tradicionales basados en firmas que solo pueden detectar amenazas previamente identificadas, estos modelos pueden reconocer patrones sutiles en el comportamiento de red que indican actividad de keylogger, incluso para variantes completamente nuevas que nunca han sido vistas antes.

**Reducción de Falsos Positivos:** Los modelos entrenados pueden distinguir entre tráfico legítimo que podría parecer sospechoso (como aplicaciones que envían datos frecuentemente) y tráfico genuinamente malicioso, reduciendo significativamente las alertas falsas que plagian los sistemas de detección tradicionales.

**Análisis en Tiempo Real:** Proporcionan capacidades de clasificación rápida que pueden procesar flujos de red en tiempo real sin impactar significativamente el rendimiento del sistema, permitiendo detección y respuesta inmediata a amenazas emergentes.

**Adaptabilidad Continua:** La arquitectura permite reentrenar y actualizar modelos con nuevos datos conforme aparecen nuevas variantes de keyloggers, manteniendo la efectividad del sistema contra amenazas evolutivas sin requerir actualizaciones manuales de reglas o firmas.

**Integración con Sistemas Existentes:** Los múltiples formatos (ONNX, pkl) y metadatos estructurados facilitan la integración con diferentes infraestructuras tecnológicas, desde sistemas embebidos con recursos limitados hasta infraestructuras enterprise con requisitos de alta disponibilidad.

## Archivos de Modelo

### 🤖 keylogger_model_large_20250918_112840.onnx
**Modelo Optimizado para Producción:** Versión ONNX del modelo Random Forest optimizada para inferencia rápida en producción. Entrenado el 18 de septiembre de 2025 a las 11:28:40, representa la versión más reciente y optimizada del modelo con capacidades de procesamiento mejoradas para entornos de alta carga.

### 🤖 modelo_keylogger_from_datos.onnx
**Modelo Base ONNX:** Versión ONNX base del modelo entrenado directamente desde los datos procesados. Proporciona capacidades de detección fundamental con optimizaciones estándar de ONNX para compatibilidad amplia.

### 🌳 rf_large_model_20250918_112442.pkl
**Modelo Random Forest Original:** Versión sklearn en formato pickle del modelo Random Forest completo. Mantiene toda la información del modelo incluyendo parámetros de entrenamiento, estadísticas internas, y capacidades de explicabilidad. Útil para análisis detallado y debugging.

### 📋 label_classes.json
**Definición de Clases:** Define las dos clases de clasificación del sistema: "Benign" para tráfico normal y "Keylogger" para actividad maliciosa. Esta definición asegura consistencia en la interpretación de predicciones a través de diferentes componentes del sistema.

### 📊 onnx_metadata_large_20250918_112840.json
**Metadatos Completos del Modelo:** Contiene información detallada sobre el modelo incluyendo las 81 características específicas analizadas, timestamps de conversión, configuraciones de entrenamiento, y especificaciones técnicas. Essential para validación de integridad y debugging.

## Ventajas de la Arquitectura de Modelos

**Múltiples Formatos:** La disponibilidad en formatos ONNX y pkl permite optimización específica para diferentes casos de uso: ONNX para producción de alta performance, pkl para desarrollo y análisis detallado.

**Modelos Versionados:** Los timestamps específicos en nombres de archivo facilitan el manejo de versiones, permitiendo despliegues graduales, A/B testing, y rollbacks seguros.

**Metadatos Ricos:** La información detallada sobre características, configuraciones, y especificaciones facilita el mantenimiento, debugging, y evolución continua del sistema.

**Validación Integrada:** Los metadatos permiten validación automática de integridad, asegurando que el modelo correcto esté siendo usado con datos en el formato esperado.

En esencia, la carpeta models representa la transformación de conocimiento experto y datos históricos en inteligencia artificial práctica que puede proteger sistemas en tiempo real contra una de las amenazas más sigilosas en ciberseguridad.