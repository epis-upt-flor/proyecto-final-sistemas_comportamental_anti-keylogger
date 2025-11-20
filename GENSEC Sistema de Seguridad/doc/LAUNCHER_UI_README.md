# 🚀 Archivos de Lanzamiento y UI - README

## Descripción General

Este documento describe los **archivos principales de ejecución** del Sistema Anti-Keylogger Unificado. Estos archivos son los puntos de entrada del sistema, proporcionando diferentes modos de operación (backend, UI, registro de plugins).

## 📋 Archivos Principales

```
UNIFIED_ANTIVIRUS/
├── launcher.py                    # Backend principal (sin UI)
├── professional_ui_robust.py      # Interfaz gráfica profesional
├── simple_backend.py              # Ejecutor del backend legacy
├── register_plugins.py            # Sistema de registro de plugins
├── install_dependencies.py        # Instalador de dependencias
├── launcher_backup.py             # Backup del launcher
└── professional_ui_robust_backup.py  # Backup de la UI
```

---

## 🎯 `launcher.py` - Punto de Entrada Principal (Backend)

**Propósito**: Ejecutar el sistema antivirus en modo backend sin interfaz gráfica

**Uso**:
```bash
# Inicio completo
python launcher.py

# Solo detectores
python launcher.py --detectors-only

# Categorías específicas
python launcher.py --categories detectors monitors

# Modo debug
python launcher.py --debug

# Archivo de configuración personalizado
python launcher.py --config my_config.toml
```

**Funcionalidad**:

### 1. Parseo de Argumentos
```python
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Sistema Anti-Keylogger Unificado - Backend"
    )
    
    parser.add_argument('--config', default='config/unified_config.toml')
    parser.add_argument('--categories', nargs='+', 
                       choices=['detectors', 'monitors', 'handlers'])
    parser.add_argument('--detectors-only', action='store_true')
    parser.add_argument('--monitors-only', action='store_true')
    parser.add_argument('--debug', action='store_true')
    
    return parser.parse_args()
```

### 2. Configuración de Logging
```python
def setup_logging(debug_mode=False):
    level = logging.DEBUG if debug_mode else logging.INFO
    
    Path('logs').mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/launcher.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
```

### 3. Inicio del Sistema
```python
def main():
    args = parse_arguments()
    setup_logging(args.debug)
    
    # Inicializar engine
    engine = UnifiedAntivirusEngine(args.config)
    
    # Determinar plugins a activar
    categories = determine_plugin_categories(args)
    
    # Iniciar sistema
    if not engine.start_system(categories):
        logger.error("Failed to start system")
        sys.exit(1)
    
    # Mantener sistema ejecutando
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        engine.shutdown_system()
```

**Descripción Técnica**:

- **Manejo de señales**: Captura SIGINT (Ctrl+C) y SIGTERM para shutdown graceful
- **Loop infinito**: Mantiene el programa ejecutándose mientras monitorea
- **Configuración flexible**: Argumentos de línea de comandos para personalización
- **Logging estructurado**: Todo evento registrado en `logs/launcher.log`
- **Error handling**: Captura errores y hace shutdown limpio

**Casos de uso**:
- **Servidor/servicio**: Ejecutar como servicio del sistema
- **Testing**: Modo debug para desarrollo
- **Producción**: Backend headless en servidor
- **CI/CD**: Integración continua y testing automatizado

---

## 🎨 `professional_ui_robust.py` - Interfaz Gráfica Profesional

**Propósito**: Proporcionar interfaz gráfica completa para gestión del antivirus

**Uso**:
```bash
python professional_ui_robust.py
```

**Funcionalidad**:

### Arquitectura de la UI

```
┌─────────────────────────────────────────────────┐
│           RobustAntivirusUI (Main Window)       │
├─────────────────────────────────────────────────┤
│  ┌───────────┬───────────┬───────────┐         │
│  │ Dashboard │  Threats  │   Logs    │         │
│  │   Tab     │    Tab    │    Tab    │         │
│  └───────────┴───────────┴───────────┘         │
│                                                  │
│  Dashboard Tab:                                 │
│  ┌──────────────────────────────────────────┐  │
│  │  [Protección: ● ACTIVA]  [⏱ 02:35:12]  │  │
│  │                                           │  │
│  │  📊 Métricas:                            │  │
│  │   • Amenazas detectadas: 5               │  │
│  │   • Plugins activos: 8                   │  │
│  │   • CPU: 15%  RAM: 250MB                │  │
│  │                                           │  │
│  │  [🛡 Iniciar Protección]                │  │
│  │  [🛑 Detener Protección]                │  │
│  └──────────────────────────────────────────┘  │
│                                                  │
│  Threats Tab:                                   │
│  ┌──────────────────────────────────────────┐  │
│  │  Amenazas Detectadas:                     │  │
│  │  ┌────────────────────────────────────┐  │  │
│  │  │ [CRITICAL] Keylogger - 10:30:15   │  │  │
│  │  │   Process: suspicious.exe          │  │  │
│  │  │   [Ver Detalles] [Cuarentena]     │  │  │
│  │  ├────────────────────────────────────┤  │  │
│  │  │ [HIGH] Network Anomaly - 10:25:03 │  │  │
│  │  │   IP: 192.168.1.100               │  │  │
│  │  └────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────┘  │
│                                                  │
│  Logs Tab:                                      │
│  ┌──────────────────────────────────────────┐  │
│  │  [2025-11-02 10:30:15] INFO: ...        │  │
│  │  [2025-11-02 10:30:20] WARNING: ...     │  │
│  │  [2025-11-02 10:30:25] ERROR: ...       │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Componentes Principales

#### 1. Clase Principal
```python
class RobustAntivirusUI:
    def __init__(self):
        self.root = tk.Tk()
        self.engine = None
        self.engine_thread = None
        self.data_queue = queue.Queue()  # Thread-safe
        
        # Control
        self.is_protection_active = False
        self.start_time = time.time()
        
        # Sistema de agregación
        self.threat_aggregator = ThreatAggregator()
        self.log_buffer = deque(maxlen=500)
        
        # Configuración de rendimiento
        self.update_interval = 5.0  # segundos
        self.pending_updates = 0
```

#### 2. Inicialización de la UI
```python
def setup_ui(self):
    # Configurar ventana principal
    self.root.title("Sistema Anti-Keylogger Unificado")
    self.root.geometry("1200x800")
    
    # Crear notebook (tabs)
    self.notebook = ttk.Notebook(self.root)
    
    # Tabs
    self.dashboard_tab = self.create_dashboard_tab()
    self.threats_tab = self.create_threats_tab()
    self.logs_tab = self.create_logs_tab()
    self.config_tab = self.create_config_tab()
    
    # Agregar tabs al notebook
    self.notebook.add(self.dashboard_tab, text="📊 Dashboard")
    self.notebook.add(self.threats_tab, text="🚨 Amenazas")
    self.notebook.add(self.logs_tab, text="📝 Logs")
    self.notebook.add(self.config_tab, text="⚙️ Configuración")
```

#### 3. Motor del Antivirus en Thread Separado
```python
def start_protection(self):
    if self.engine_running.is_set():
        return
    
    # Iniciar engine en thread separado
    self.engine_thread = threading.Thread(
        target=self._run_engine,
        daemon=True
    )
    self.engine_thread.start()
    
    # Iniciar actualización de UI
    self.schedule_ui_update()

def _run_engine(self):
    """Ejecuta en thread separado"""
    self.engine = UnifiedAntivirusEngine()
    self.engine_running.set()
    
    if self.engine.start_system(['detectors', 'monitors', 'handlers']):
        # Suscribir a eventos
        event_bus.subscribe('threat_detected', self._on_threat_detected, 'UI')
        event_bus.subscribe('system_update', self._on_system_update, 'UI')
```

#### 4. Actualización Asíncrona de UI
```python
def _on_threat_detected(self, event):
    """Callback del event bus (en thread del engine)"""
    # Poner en queue para procesamiento en UI thread
    self.data_queue.put({
        'type': 'threat',
        'data': event.data
    })

def schedule_ui_update(self):
    """Programar actualización periódica (UI thread)"""
    self.update_ui_from_queue()
    
    # Reprogramar
    self.root.after(
        int(self.update_interval * 1000),
        self.schedule_ui_update
    )

def update_ui_from_queue(self):
    """Procesar eventos de la queue (UI thread)"""
    try:
        # Procesar hasta 10 eventos por actualización
        for _ in range(10):
            event = self.data_queue.get_nowait()
            
            if event['type'] == 'threat':
                self._add_threat_to_ui(event['data'])
            elif event['type'] == 'log':
                self._add_log_to_ui(event['data'])
                
    except queue.Empty:
        pass
```

#### 5. Sistema de Agregación de Amenazas
```python
class ThreatAggregator:
    """Agrega amenazas duplicadas para evitar spam en UI"""
    
    def __init__(self):
        self.threats = {}  # threat_signature -> count
        self.last_shown = {}
    
    def add_threat(self, threat_data):
        signature = self._generate_signature(threat_data)
        
        if signature in self.threats:
            self.threats[signature]['count'] += 1
            # Solo mostrar si pasó suficiente tiempo
            if time.time() - self.last_shown[signature] > 60:
                self.last_shown[signature] = time.time()
                return True  # Mostrar
            return False  # No mostrar (duplicado reciente)
        else:
            self.threats[signature] = {'data': threat_data, 'count': 1}
            self.last_shown[signature] = time.time()
            return True  # Mostrar (nuevo)
```

**Descripción Técnica**:

**Características clave**:
- **Threading**: Engine en thread separado, UI en main thread
- **Queue-based communication**: Thread-safe con `queue.Queue`
- **Agregación de datos**: Reduce spam de amenazas duplicadas
- **Buffer circular**: `deque` con límite para logs
- **Actualización incremental**: UI actualiza cada 5 segundos
- **Performance optimizations**: Limita updates pendientes

**Consideraciones**:
- **No blocking**: UI nunca se congela
- **Memory efficient**: Buffers con límites
- **User-friendly**: Feedback visual claro
- **Responsive**: Actualiza en tiempo real pero sin saturar

---

## 🔌 `register_plugins.py` - Sistema de Registro

**Propósito**: Registrar automáticamente todos los plugins del sistema

**Uso**:
```python
from register_plugins import register_all_plugins

# Registrar todos los plugins
register_all_plugins()

# Ahora el PluginManager puede descubrirlos
```

**Funcionalidad**:
```python
def register_all_plugins():
    registry = PluginRegistry()
    
    # Registrar detectores
    try:
        from plugins.detectors.ml_detector.plugin import MLDetectorPlugin
        registry.register_plugin(MLDetectorPlugin, 'ml_detector', 'detectors')
    except ImportError as e:
        logger.warning(f"ML Detector no disponible: {e}")
    
    try:
        from plugins.detectors.behavior_detector import BehaviorDetectorPlugin
        registry.register_plugin(BehaviorDetectorPlugin, 'behavior_detector', 'detectors')
    except ImportError as e:
        logger.warning(f"Behavior Detector no disponible: {e}")
    
    # ... más plugins ...
    
    # Registrar monitores
    try:
        from plugins.monitors.process_monitor import ProcessMonitorPlugin
        registry.register_plugin(ProcessMonitorPlugin, 'process_monitor', 'monitors')
    except ImportError as e:
        logger.warning(f"Process Monitor no disponible: {e}")
    
    # ... más monitores ...
    
    # Registrar handlers
    # ...
```

**Descripción Técnica**:
- **Graceful imports**: Fallo en un plugin no detiene el sistema
- **Logging**: Registra qué plugins se cargan exitosamente
- **Registry Pattern**: Usa PluginRegistry para registro centralizado
- **Flexible**: Fácil añadir nuevos plugins

---

## 💾 `simple_backend.py` - Ejecutor Legacy

**Propósito**: Ejecutar el sistema ANTIVIRUS_PRODUCTION legacy

**Uso**:
```bash
python simple_backend.py
```

**Funcionalidad**:
```python
def main():
    print("🛡️  Ejecutando Sistema Backend Original")
    
    # Ruta al backend legacy
    backend_path = Path(__file__).parent.parent / "ANTIVIRUS_PRODUCTION"
    launcher_file = backend_path / "antivirus_launcher.py"
    
    # Verificar existe
    if not launcher_file.exists():
        print(f"❌ Error: No se encuentra {launcher_file}")
        sys.exit(1)
    
    # Cambiar directorio y ejecutar
    original_cwd = os.getcwd()
    
    try:
        os.chdir(backend_path)
        subprocess.run([sys.executable, "antivirus_launcher.py"])
    finally:
        os.chdir(original_cwd)
```

**Descripción Técnica**:
- **Compatibilidad**: Ejecuta sistema antiguo sin modificaciones
- **Working directory**: Cambia CWD temporalmente
- **Subprocess**: Ejecución aislada
- **Cleanup**: Restore working directory en finally

---

## 📦 `install_dependencies.py` - Instalador

**Propósito**: Instalar todas las dependencias del sistema

**Uso**:
```bash
python install_dependencies.py
```

**Funcionalidad**:
```python
def main():
    print("📦 Instalando dependencias del Sistema Anti-Keylogger")
    
    # Verificar pip
    try:
        import pip
    except ImportError:
        print("pip no encontrado, instalando...")
        install_pip()
    
    # Leer requirements
    requirements_file = 'xd/requirements.txt'
    
    # Instalar
    subprocess.check_call([
        sys.executable, '-m', 'pip', 'install',
        '-r', requirements_file
    ])
    
    print("✅ Dependencias instaladas exitosamente")
    
    # Verificar instalación
    verify_installation()
```

---

## 🔄 Flujo de Ejecución Completo

### Opción 1: Backend Headless
```bash
python launcher.py --detectors-only
```
```
1. Parsear argumentos
2. Setup logging
3. Inicializar UnifiedAntivirusEngine
4. Cargar solo detectores
5. Loop infinito (monitoreo en background)
6. CTRL+C → Shutdown graceful
```

### Opción 2: UI Completa
```bash
python professional_ui_robust.py
```
```
1. Crear ventana tkinter
2. Setup tabs y widgets
3. Usuario click "Iniciar Protección"
4. Engine inicia en thread separado
5. UI actualiza cada 5 segundos desde queue
6. Usuario interactúa (ver amenazas, configuración)
7. Usuario click "Detener" → Shutdown
```

---

## 💡 Mejores Prácticas

**Para launcher.py**:
- Usar argumentos para flexibilidad
- Logging apropiado
- Manejar señales correctamente
- Cleanup en shutdown

**Para professional_ui_robust.py**:
- Nunca bloquear UI thread
- Usar queue para comunicación entre threads
- Limitar updates para performance
- Agregar amenazas duplicadas

**Para register_plugins.py**:
- Mantener actualizado con nuevos plugins
- Manejar imports fallidos gracefully
- Logging de registro

---

## 🧪 Testing

```python
# Test launcher
def test_launcher_arguments():
    args = parse_arguments(['--detectors-only'])
    assert args.detectors_only == True

# Test UI (unit test, no ejecutar window)
def test_ui_threat_aggregation():
    aggregator = ThreatAggregator()
    
    threat = {'type': 'keylogger', 'process': 'test.exe'}
    
    assert aggregator.add_threat(threat) == True  # Primera vez
    assert aggregator.add_threat(threat) == False  # Duplicado
```

---

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025  
**Plataformas soportadas**: Windows 10/11, Linux, macOS
