# 🖥️ GENSEC - Frontend Interface

## 📋 Descripción

Frontend moderno y profesional del sistema antivirus GENSEC, construido con **Dear PyGui** para ofrecer una interfaz gráfica acelerada por GPU con alto rendimiento y experiencia de usuario superior.

## ✨ Características Principales

### 🎛️ **Interfaz de Usuario**
- **Rendimiento GPU**: Aceleración por hardware para gráficos fluidos
- **Tema Oscuro Profesional**: Diseño moderno y fácil para los ojos
- **Dashboard Interactivo**: Métricas en tiempo real del sistema
- **Multi-vista**: Navegación por pestañas entre diferentes secciones

### 🔍 **Monitor en Tiempo Real (Live TTPs Log)**
- **Detección Activa**: Visualización de amenazas detectadas en tiempo real
- **Acciones Forenses**: Botones funcionales para gestión de amenazas:
  - ⚖️ **Weighting**: Detalles de análisis de consenso
  - 🛑 **End Test**: Terminación de procesos sospechosos
  - 🔒 **Isolate**: Cuarentena de archivos maliciosos
  - 📍 **Locate**: Abrir ubicación del archivo en explorador

### 📊 **Análisis de Consenso**
- **Ponderación Detallada**: Visualización de cómo se calcula el riesgo
- **Múltiples Detectores**: Combinación de diferentes motores de detección
- **Scoring Transparente**: Puntuaciones ponderadas y finales

### ⚙️ **Configuración Avanzada**
- **Protección en Tiempo Real**: Activar/desactivar monitoreo continuo
- **Auto-cuarentena**: Aislamiento automático de amenazas de alto riesgo
- **Sensibilidad ML**: Ajuste fino del modelo de machine learning
- **Configuración de Recursos**: Límites de CPU y memoria

## 🏗️ Arquitectura

```
frontend/
├── main.py                 # Aplicación principal y controlador
├── components/            # Componentes modulares de UI
│   ├── dashboard.py       # Panel principal con métricas
│   ├── realtime_monitor.py # Monitor de amenazas en vivo
│   ├── threat_viewer.py   # Visor detallado de amenazas
│   ├── consensus_viewer.py # Análisis de consenso
│   ├── settings.py        # Panel de configuración
│   └── logs_viewer.py     # Visualizador de logs
├── themes/               # Temas y estilos
│   └── dark_theme.py     # Tema oscuro profesional
└── utils/               # Utilidades del frontend
    └── performance_monitor.py # Monitor de rendimiento
```

## 🚀 Instalación y Uso

### **Prerrequisitos**
```bash
pip install -r requirements.txt
```

**Dependencias principales:**
- `dearpygui` - Framework de UI con aceleración GPU
- `psutil` - Gestión de procesos del sistema
- `pathlib` - Manipulación avanzada de rutas

### **Ejecución**

#### **Modo Desarrollo**
```bash
cd frontend
python main.py
```

#### **Modo Producción**
```bash
# Desde directorio raíz
python production_launcher.py
```

#### **Modo Desarrollo con Backend**
```bash
python backend_launcher.py
```

## 🎯 Componentes Principales

### **AntivirusProfessionalUI** 
Clase principal que gestiona toda la interfaz y coordinación con el backend.

**Funcionalidades clave:**
- Integración con motores de detección (`UnifiedAntivirusEngine`, `SimpleAntivirusEngine`)
- Gestión de amenazas activas y cuarentena
- Sistema de métricas y monitoreo de rendimiento
- Configuración persistente de usuario

### **RealtimeMonitorComponent**
Monitor en tiempo real de amenazas con capacidades de acción inmediata.

**Características:**
- Actualización automática cada 1-5 segundos (configurable)
- Datos reales de procesos del sistema
- Acciones forenses completas (stop, quarantine, analyze, locate)

### **Integración Backend**
El frontend se integra seamlessly con el backend existente:

```python
# Detección automática del motor disponible
try:
    from core.engine import UnifiedAntivirusEngine
    BACKEND_TYPE = "FULL"
except ImportError:
    from core.simple_engine import SimpleAntivirusEngine
    BACKEND_TYPE = "SIMPLE"
```

## 🔧 Configuración

### **Archivo de Configuración**
```json
{
    "realtime_protection": true,
    "auto_quarantine": true,
    "ml_sensitivity": 75,
    "behavior_threshold": 70,
    "gpu_acceleration": true,
    "max_cpu_usage": 30,
    "max_memory_mb": 512,
    "scan_interval_seconds": 5
}
```

### **Configuración de Logging**
```python
# Logs almacenados en: logs/frontend.log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## 🛠️ Desarrollo

### **Estructura del Código**
- **Patrón MVC**: Separación clara entre vista, modelo y controlador
- **Componentes Modulares**: Cada vista es un componente independiente
- **Event-Driven**: Callbacks y actualizaciones asíncronas
- **Thread-Safe**: Manejo seguro de hilos para UI responsiva

### **Agregar Nuevos Componentes**
```python
# 1. Crear clase component
class NewComponent:
    def __init__(self, parent_tag: str, app_controller):
        self.parent_tag = parent_tag
        self.app_controller = app_controller
    
    def render(self):
        # Implementar UI con Dear PyGui
        pass

# 2. Registrar en main.py
self.new_component = NewComponent("new_view", self)

# 3. Agregar navegación
def switch_view(self, view_name: str):
    views = ["dashboard", "realtime_monitor", "new_view"]  # Agregar aquí
```

## 🔒 Seguridad

### **Validaciones Implementadas**
- ✅ Verificación de existencia de archivos antes de cuarentena
- ✅ Validación de PIDs antes de terminación de procesos
- ✅ Sanitización de paths para evitar directory traversal
- ✅ Manejo seguro de excepciones en operaciones críticas

### **Permisos Requeridos**
- **Lectura de procesos**: Para mostrar información de procesos activos
- **Terminación de procesos**: Para la funcionalidad "End Test"
- **Gestión de archivos**: Para cuarentena y ubicación de archivos

## 📈 Rendimiento

### **Optimizaciones**
- **GPU Acceleration**: Dear PyGui utiliza OpenGL/DirectX
- **Lazy Loading**: Componentes se cargan bajo demanda
- **Threading**: Operaciones pesadas en hilos separados
- **Caching**: Datos de sistema cacheados inteligentemente

### **Métricas Monitoreadas**
- CPU usage del frontend
- Memoria RAM utilizada
- Tiempo de respuesta de UI
- Frecuencia de actualización de amenazas

## 🐛 Solución de Problemas

### **Problemas Comunes**

#### **Error: PluginManager has no attribute 'plugins'**
**Solución**: Actualizado para usar `active_plugins` en lugar de `plugins`

#### **Error: Proceso no encontrado**
**Solución**: El sistema ahora usa PIDs reales de procesos activos

#### **Error: Archivo no existe para cuarentena**
**Solución**: Validación de existencia de archivo implementada

#### **Botones no funcionan**
**Solución**: Todos los botones tienen funcionalidad completa implementada

### **Logs de Debug**
```bash
# Ubicación de logs
logs/frontend.log
logs/realtime_monitor.log

# Ver logs en tiempo real
tail -f logs/frontend.log
```

## 📝 Changelog

### **v2.1.0** - Noviembre 2025
- ✅ Solucionados errores de botones "End Test" e "Isolate"
- ✅ Implementada funcionalidad completa de "Weighting" button
- ✅ Mejorada validación de archivos y procesos
- ✅ Integración mejorada con PluginManager backend
- ✅ Datos reales de procesos del sistema

### **v2.0.0** - 2025
- 🆕 Migración completa a Dear PyGui
- 🆕 Aceleración GPU
- 🆕 Tema oscuro profesional
- 🆕 Componentes modulares

## 🤝 Contribución

1. Fork el repositorio
2. Crear branch de feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push al branch (`git push origin feature/nueva-funcionalidad`)
5. Crear Pull Request

## 📄 Licencia

Este proyecto está bajo la licencia especificada en el repositorio principal.

---

**GENSEC Sistema de Seguridad** - Frontend Interface v2.1.0
*Desarrollado con ❤️ usando Dear PyGui*