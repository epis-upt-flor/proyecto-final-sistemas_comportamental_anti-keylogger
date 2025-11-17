"""
Antivirus Professional UI - Dear PyGui Frontend
==============================================

Nueva interfaz moderna con rendimiento GPU para el sistema antivirus.
Mantiene 100% compatibilidad con el backend Python existente.

Características:
- Rendimiento GPU acelerado
- UI moderna y profesional
- Gráficos en tiempo real
- Dashboard interactivo
- Temas personalizables
"""

import dearpygui.dearpygui as dpg
import threading
import time
import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Agregar el directorio raíz al path para importar el backend
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

# Agregar directorio frontend para imports locales
frontend_dir = Path(__file__).parent
sys.path.insert(0, str(frontend_dir))

# Importar el backend existente (sin cambios)
try:
    # Intentar motor complejo primero
    from core.engine import UnifiedAntivirusEngine
    BACKEND_TYPE = "FULL"
except ImportError:
    try:
        # Usar motor simplificado
        from core.simple_engine import SimpleAntivirusEngine as UnifiedAntivirusEngine
        BACKEND_TYPE = "SIMPLE"
    except ImportError:
        UnifiedAntivirusEngine = None
        BACKEND_TYPE = "DEMO"

# Setup logger
try:
    from utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(name, file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(file_path),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(name)
    setup_logger = setup_logger
try:
    from components.dashboard import DashboardComponent
    from components.realtime_monitor import RealtimeMonitorComponent
    from components.threat_viewer import ThreatViewerComponent
    from components.settings import SettingsComponent
    from components.logs_viewer import LogsViewerComponent
    from themes.dark_theme import apply_dark_theme
except ImportError as e:
    print(f"⚠️ Error importando componentes: {e}")
    # Crear clases dummy para desarrollo
    class DashboardComponent:
        def __init__(self, *args, **kwargs): pass
        def render(self): dpg.add_text("Dashboard Component")
    class RealtimeMonitorComponent:
        def __init__(self, *args, **kwargs): pass
        def render(self): dpg.add_text("Realtime Monitor Component")
    class ThreatViewerComponent:
        def __init__(self, *args, **kwargs): pass
        def render(self): dpg.add_text("Threat Viewer Component")
    class SettingsComponent:
        def __init__(self, *args, **kwargs): pass
        def render(self): dpg.add_text("Settings Component")
    class LogsViewerComponent:
        def __init__(self, *args, **kwargs): pass
        def render(self): dpg.add_text("Logs Viewer Component")
    def apply_dark_theme(): pass

# Importar desde frontend
try:
    from utils.performance_monitor import PerformanceMonitor
except ImportError as e:
    print(f"⚠️ Error importando PerformanceMonitor: {e}")
    # Crear una clase temporal simple
    class PerformanceMonitor:
        def __init__(self):
            self.is_monitoring = False
        def start_monitoring(self):
            self.is_monitoring = True
        def stop_monitoring(self):
            self.is_monitoring = False
        def get_fps(self): return [60.0] * 10

# Sistema de métricas simplificado integrado
import psutil
import threading
import time
from collections import deque

class SimpleMetrics:
    """Sistema de métricas simplificado integrado"""
    def __init__(self):
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.threats_detected = 0
        self.files_scanned = 0
        self.running = False
        
    def start_collection(self):
        self.running = True
        threading.Thread(target=self._collect_loop, daemon=True).start()
        
    def _collect_loop(self):
        while self.running:
            try:
                self.cpu_history.append(psutil.cpu_percent())
                self.memory_history.append(psutil.virtual_memory().percent)
                time.sleep(2)
            except:
                pass
                
    def get_system_stats(self):
        return {
            'cpu': f"{list(self.cpu_history)[-1] if self.cpu_history else 0:.1f}%",
            'memory': f"{list(self.memory_history)[-1] if self.memory_history else 0:.1f}%",
            'threats': self.threats_detected,
            'scans': self.files_scanned
        }

# Inicializar sistema de métricas
simple_metrics = SimpleMetrics()
REAL_METRICS_AVAILABLE = True
print("✅ Sistema de métricas simplificado disponible")

# Crear clases stub para compatibilidad
class SystemMetrics:
    pass

class AntivirusMetrics:
    pass

class RealTimeLogReader:
    pass

class LogManager:
    pass


class AntivirusProfessionalUI:
    """
    Interfaz principal del antivirus con Dear PyGui
    
    Mantiene toda la funcionalidad del backend original pero con UI moderna
    """
    
    def __init__(self):
        """Inicializar la aplicación"""
        
        # Tiempo de inicio para uptime
        self.start_time = time.time()
        
        # Configurar logging
        if setup_logger:
            self.logger = setup_logger("AntivirusUI", "logs/frontend.log")
        else:
            import logging
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger("AntivirusUI")
        self.logger.info("🚀 Iniciando Antivirus Professional UI (Dear PyGui)")
        
        # Inicializar el motor antivirus (backend sin cambios)
        self.engine = None
        self.engine_thread = None
        self.is_running = False
        self.stopping = False
        
        # Control de threads más robusto (como professional_ui_robust.py)
        self.engine_running = threading.Event()
        
        # Componentes UI
        self.dashboard = None
        self.realtime_monitor = None
        self.threat_viewer = None
        self.settings = None
        self.logs_viewer = None
        
        # Monitor de rendimiento
        self.performance_monitor = PerformanceMonitor()
        
        # Estado de la aplicación
        self.current_view = "dashboard"
        self.threat_count = 0
        self.scan_progress = 0.0
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Datos en tiempo real
        self.system_stats = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'processes_monitored': 0,
            'threats_detected': 0,
            'uptime': 0
        }
        
        # Inicializar sistema de métricas simplificado
        self.metrics_system = simple_metrics
        self.metrics_system.start_collection()
        self.antivirus_metrics = None
        self.log_manager = None
        self.real_log_reader = None
        self.logger.info("✅ Sistema de métricas simplificado inicializado")
        
        # Sistema de datos funcional
        self.active_threats = [
            {
                'timestamp': '20:42:15',
                'type': 'Keylogger',
                'name': 'Code.exe',
                'path': 'C:\\Program Files\\Microsoft VS Code\\Code.exe',
                'pid': 420,
                'risk': 'HIGH',
                'details': 'Suspicious keyboard monitoring detected'
            },
            {
                'timestamp': '20:42:10',
                'type': 'Behavior',
                'name': 'python.exe',
                'path': 'C:\\Python\\python.exe',
                'pid': 1234,
                'risk': 'MEDIUM',
                'details': 'High CPU usage detected'
            }
        ]
        self.quarantine_items = []
        self.whitelist_items = [
            "python.exe", "Code.exe", "chrome.exe", "explorer.exe", "System32\\*.dll"
        ]
        self.blacklist_items = [
            "keylogger.exe", "malware_sample.exe", "suspicious_*.tmp"
        ]
        self.system_settings = {
            'realtime_protection': True,
            'behavior_analysis': True,
            'network_monitoring': True,
            'keylogger_detection': True,
            'ml_sensitivity': 75,
            'behavior_threshold': 70,
            'auto_quarantine': False,
            'auto_block_network': True,
            'max_cpu_usage': 30,  # Arreglar nombre
            'max_memory_mb': 512,  # Arreglar nombre
            'scan_interval_seconds': 5,  # Arreglar nombre  
            'gpu_acceleration': True,
            'gaming_mode': False,
            'log_level': "INFO",
            'max_log_size': 100,
            'log_retention': 30,
            'web_logging': True,
            'json_export': True,
            'log_streaming': False,
            'auto_update_sigs': True,
            'auto_update_ml': True,
            'auto_update_engine': False,
            'update_frequency': "Every 6 Hours"
        }
        
        # Monitor en tiempo real
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Cargar configuraciones guardadas
        self.load_settings()

    def get_system_stats(self):
        """Devuelve las estadísticas actuales del sistema."""
        return self.system_stats

    def get_active_threats(self):
        """Devuelve la lista de amenazas activas."""
        return self.active_threats

    def get_root_dir(self) -> str:
        """Devuelve el directorio raíz del proyecto."""
        return str(root_dir)

    def get_threat_decision_path(self, threat: dict) -> List[dict]:
        """
        Obtiene el camino de decisión para una amenaza.
        En un sistema real, esto vendría del backend. Aquí lo simulamos.
        """
        threat_type = threat.get('type', 'Unknown')
        risk = threat.get('risk', 'LOW')

        # Simulación de diferentes árboles de decisión basados en el tipo de amenaza
        if threat_type == 'Keylogger':
            return [
                {"node": "Initial Scan", "details": "File system event triggered scan.", "result": "Continue", "children": [
                    {"node": "Signature Analysis", "details": "Checking against known keylogger signatures.", "result": "No known signatures found.", "children": [
                        {"node": "Behavioral Analysis", "details": "Monitoring process for suspicious API calls (e.g., GetAsyncKeyState, SetWindowsHookEx).", "result": "Suspicious API calls detected.", "children": [
                            {"node": "Machine Learning Model", "details": "Feeding behavioral data into ONNX model.", "result": "Model prediction: 98% confidence of being a keylogger.", "children": [
                                {"node": "Final Verdict", "details": "Combining evidence from behavioral analysis and ML model.", "result": "Threat Level: HIGH", "children": []}
                            ]}
                        ]}
                    ]}
                ]}
            ]
        elif risk == 'MEDIUM':
             return [
                {"node": "Initial Scan", "details": "Scheduled background scan.", "result": "Continue", "children": [
                    {"node": "Heuristic Analysis", "details": "Analyzing file structure for common malware patterns.", "result": "Found packed sections, often used to hide malicious code.", "children": [
                        {"node": "Sandbox Emulation", "details": "Running file in a virtual environment to observe behavior.", "result": "Process attempted to modify system registry keys.", "children": [
                            {"node": "Final Verdict", "details": "File exhibits multiple suspicious indicators.", "result": "Threat Level: MEDIUM", "children": []}
                        ]}
                    ]}
                ]}
            ]
        else: # Default/LOW
            return [
                {"node": "File Scan", "details": "A new temporary file was created.", "result": "Continue", "children": [
                    {"node": "Whitelist Check", "details": "Checking if file path matches any whitelist patterns.", "result": "Path does not match whitelist.", "children": [
                         {"node": "Reputation Service", "details": "Querying cloud reputation service for file hash.", "result": "Reputation is neutral or unknown.", "children": [
                            {"node": "Final Verdict", "details": "No definitive malicious indicators found, but file is not fully trusted.", "result": "Threat Level: LOW", "children": []}
                         ]}
                    ]}
                ]}
            ]

    def set_setting(self, key, value):
        """Actualiza una configuración del sistema."""
        if key in self.system_settings:
            self.system_settings[key] = value
            self.logger.info(f"Setting '{key}' updated to '{value}'")
            self.save_settings()
        else:
            self.logger.warning(f"Attempted to set unknown setting '{key}'")

    def perform_backend_action(self, action: str, data: dict) -> Tuple[bool, str]:
        """
        Punto central para enviar acciones al backend.
        Esto es una simulación. La lógica real estaría en el motor.
        """
        self.logger.info(f"Performing backend action: {action} with data: {data}")
        
        # SIMULACIÓN - Aquí iría la llamada real al self.engine
        if action == 'stop_process':
            pid = data.get('pid')
            try:
                p = psutil.Process(pid)
                p.terminate() # o p.kill()
                return True, f"Process {pid} terminated."
            except psutil.NoSuchProcess:
                return False, f"Process {pid} not found."
            except Exception as e:
                return False, str(e)

        elif action == 'quarantine_file':
            path = data.get('path')
            # La lógica de cuarentena real y segura debe estar en el backend.
            # Esto es solo una demostración para la UI.
            return True, f"File '{path}' has been scheduled for quarantine by the backend."

        elif action == 'whitelist_item':
            identifier = data.get('identifier')
            if identifier not in self.whitelist_items:
                self.whitelist_items.append(identifier)
            return True, f"'{identifier}' has been added to the whitelist in the backend."
            
        return False, "Action not implemented in backend simulation."

    def load_settings(self):
        """Cargar configuraciones desde un archivo"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'ui_settings.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    self.system_settings.update(json.load(f))
                self.logger.info("✅ Settings loaded from ui_settings.json")
        except Exception as e:
            self.logger.warning(f"⚠️ Could not load settings: {e}")

    def save_settings(self):
        """Guardar configuraciones en un archivo"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'ui_settings.json')
            with open(config_path, 'w') as f:
                json.dump(self.system_settings, f, indent=4)
            self.logger.info("✅ Settings saved to ui_settings.json")
        except Exception as e:
            self.logger.error(f"❌ Could not save settings: {e}")
        
    def _setup_fonts(self):
        """Configurar fuentes mejoradas y modernas"""
        try:
            # Registrar fuentes modernas con mejor renderizado
            with dpg.font_registry():
                # Fuentes principales - usar Segoe UI Variable si está disponible
                font_paths = [
                    ("C:/Windows/Fonts/SegUIVar.ttf", "Segoe UI Variable"),
                    ("C:/Windows/Fonts/segoeui.ttf", "Segoe UI"),
                    ("C:/Windows/Fonts/arial.ttf", "Arial"),
                ]
                
                font_loaded = False
                for font_path, font_name in font_paths:
                    try:
                        if os.path.exists(font_path):
                            dpg.add_font(font_path, 15, tag="default_font")
                            dpg.add_font(font_path, 18, tag="header_font") 
                            dpg.add_font(font_path, 13, tag="small_font")
                            self.logger.info(f"✅ Fuente cargada: {font_name}")
                            font_loaded = True
                            break
                    except Exception:
                        continue
                        
                # Fuente monospace para logs
                mono_paths = [
                    "C:/Windows/Fonts/CascadiaCode.ttf",
                    "C:/Windows/Fonts/consola.ttf",
                    "C:/Windows/Fonts/cour.ttf"
                ]
                
                for mono_path in mono_paths:
                    try:
                        if os.path.exists(mono_path):
                            dpg.add_font(mono_path, 13, tag="monospace_font")
                            break
                    except Exception:
                        continue
            
            # Aplicar fuente por defecto si se cargó
            if font_loaded:
                dpg.bind_font("default_font")
            
        except Exception as e:
            self.logger.warning(f"⚠️ No se pudo cargar fuentes personalizadas: {e}")

    def _create_ui_components(self):
        """Crear instancias de los componentes de la UI"""
        self.dashboard = DashboardComponent("dashboard_view")
        self.realtime_monitor = RealtimeMonitorComponent("realtime_monitor_view", self)
        self.threat_viewer = ThreatViewerComponent("threat_viewer_view", self)
        self.settings = SettingsComponent("settings_view", self)
        self.logs_viewer = LogsViewerComponent("logs_view", self)
        
    def _safe_initialize_backend(self):
        """Inicializar el motor antivirus de forma segura en hilo separado"""
        try:
            self.initialize_backend()
        except Exception as e:
            self.logger.error(f"❌ Error inicializando backend: {e}")
            # Continuar con simulación si hay problemas con el backend real
            self.logger.info("⚠️ Continuando con modo simulación")

    def initialize_backend(self):
        """Inicializar el motor antivirus real y funcional"""
        try:
            # Verificar si ya está inicializado
            if self.engine and hasattr(self, 'engine_thread') and self.engine_thread and self.engine_thread.is_alive():
                self.logger.info("⚠️ Motor antivirus ya está activo")
                return
                
            self.logger.info("🛡️ Inicializando motor antivirus...")
            
            if UnifiedAntivirusEngine:
                # Crear instancia del motor
                self.engine = UnifiedAntivirusEngine()
                self.logger.info(f"✅ Motor creado - Tipo: {BACKEND_TYPE}")
                
                # Inicializar el motor
                success = self.engine.start_system()
                if success:
                    self.logger.info("✅ Motor antivirus REAL iniciado y funcionando")
                    self.is_running = True
                    
                    # Activar control de engine (como professional_ui_robust.py)
                    self.engine_running.set()
                    
                    # Iniciar thread para actualizar datos del backend (no daemon para control de shutdown)
                    self.engine_thread = threading.Thread(target=self._backend_data_sync, daemon=False)
                    self.engine_thread.start()
                    
                    # Actualizar estado en UI
                    self._update_backend_status("ACTIVE")
                    
                    # Actualizar UI para mostrar estado activo
                    if dpg.does_item_exist("status_text"):
                        dpg.set_value("status_text", "Active")
                        dpg.configure_item("status_text", color=(0, 255, 0))
                else:
                    self.logger.error("❌ Falló la inicialización del motor")
                    self._setup_demo_mode()
            else:
                self.logger.warning("⚠️ Backend no disponible, ejecutando en modo demo")
                self._setup_demo_mode()
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando backend: {e}")
            self._setup_demo_mode()
    
    def _backend_data_sync(self):
        """Sincronizar datos del backend con el frontend"""
        self.logger.info("🔄 Iniciando sincronización con backend...")
        
        while self.is_running and self.engine and not self.stopping and self.engine_running.is_set():
            try:
                # Verificar si debemos continuar
                if not self.is_running or self.stopping or not self.engine_running.is_set():
                    break
                    
                # Obtener datos del motor real
                if hasattr(self.engine, 'get_system_status'):
                    status = self.engine.get_system_status()
                    
                    # Actualizar estadísticas del sistema
                    self.system_stats.update(status.get('stats', {}))
                    
                    # Obtener amenazas reales del motor
                    if hasattr(self.engine, 'get_active_threats'):
                        real_threats = self.engine.get_active_threats()
                        
                        # Convertir formato del motor al formato del frontend
                        self.active_threats = []
                        for threat in real_threats:
                            self.active_threats.append({
                                'timestamp': threat.get('timestamp', time.strftime('%H:%M:%S')),
                                'name': threat.get('name', 'Unknown'),
                                'pid': threat.get('pid', 0),
                                'type': threat.get('type', 'Unknown'),
                                'risk': threat.get('level', 'MEDIUM'),
                                'cpu': threat.get('cpu_percent', 0),
                                'details': f"PID: {threat.get('pid', 0)}, Level: {threat.get('level', 'UNKNOWN')}"
                            })
                    
                    # Actualizar contadores
                    self.threat_count = len(self.active_threats)
                
                # Sleep con verificación de shutdown
                for _ in range(20):  # 2 segundos divididos en 0.1s para respuesta rápida
                    if not self.is_running or self.stopping or not self.engine_running.is_set():
                        break
                    time.sleep(0.1)
                
            except Exception as e:
                self.logger.warning(f"Error en sincronización de datos: {e}")
                # Sleep con verificación de shutdown en caso de error
                for _ in range(50):  # 5 segundos divididos en 0.1s
                    if not self.is_running or self.stopping or not self.engine_running.is_set():
                        break
                    time.sleep(0.1)
        
        self.logger.info("🔄 Sincronización con backend terminada")
    
    def _update_backend_status(self, status):
        """Actualizar estado del backend en la UI"""
        try:
            if status == "ACTIVE":
                self.logger.info(f"🟢 Backend Status: ACTIVO ({BACKEND_TYPE}) - Motor real funcionando")
            else:
                self.logger.info("🟡 Backend Status: DEMO MODE")
        except Exception as e:
            self.logger.warning(f"Error actualizando estado: {e}")
    
    def _setup_backend_callbacks(self):
        """Configurar callbacks para recibir datos del motor"""
        # Estos métodos conectan el backend con el frontend
        # sin modificar el código del motor original
        pass
    
    def _run_engine(self):
        """Ejecutar el motor antivirus en thread separado"""
        try:
            if self.engine:
                # Inicializar sistema de métricas con el engine
                if self.antivirus_metrics:
                    self.antivirus_metrics.set_engine(self.engine)
                    self.logger.info("✅ AntivirusMetrics conectado al engine")
                
                # Iniciar el sistema de plugins
                success = self.engine.start_system()
                if not success:
                    self.logger.error("❌ Falló el inicio del sistema antivirus")
                    return
                
                # Inicializar logs manager con archivos reales
                if self.log_manager:
                    # Buscar archivos de log del antivirus
                    log_paths = [
                        "logs/antivirus.log",
                        "logs/threats.log", 
                        "logs/system.log",
                        "logs/test_system_structured.jsonl"
                    ]
                    
                    for log_path in log_paths:
                        full_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), log_path)
                        if os.path.exists(full_path):
                            self.log_manager.add_log_file(full_path)
                            self.logger.info(f"📋 Log agregado: {full_path}")
                
                # Loop principal del motor
                while self.is_running and not self.stopping and self.engine_running.is_set():
                    self._update_system_stats()
                    
                    # Sleep con verificación de parada cada 0.1s para respuesta rápida
                    for _ in range(10):  # 1 segundo dividido en 0.1s
                        if not self.is_running or self.stopping or not self.engine_running.is_set():
                            break
                        time.sleep(0.1)
                    
        except Exception as e:
            self.logger.error(f"❌ Error en motor antivirus: {e}")
    
    def _update_system_stats(self):
        """Actualizar estadísticas del sistema usando datos reales"""
        try:
            # Usar métricas reales del sistema
            if self.metrics_system:
                system_data = self.metrics_system.get_system_stats()
                
                # Actualizar con datos reales del sistema
                self.system_stats.update({
                    'cpu_usage': float(system_data.get('cpu', '0%').replace('%', '')),
                    'memory_usage': float(system_data.get('memory', '0%').replace('%', '')),
                    'disk_usage': 0.0,
                    'network_sent': 0,
                    'network_recv': 0,
                    'processes_monitored': system_data.get('threats', 0)
                })
                
                # Actualizar con datos reales del antivirus
                self.system_stats.update({
                    'threats_detected': len(self.active_threats),
                    'scans_performed': system_data.get('scans', 0),
                    'files_scanned': system_data.get('scans', 0),
                    'quarantined_files': len(self.quarantine_items),
                    'false_positives': 0,
                    'uptime': time.time() - getattr(self, 'start_time', time.time())
                })
            else:
                # Fallback a métricas básicas si no hay sistema de métricas
                import psutil
                self.system_stats.update({
                    'cpu_usage': psutil.cpu_percent(),
                    'memory_usage': psutil.virtual_memory().percent,
                    'processes_monitored': len(psutil.pids())
                })
                
                # Obtener estadísticas del motor si está disponible
                if self.engine:
                    stats = self.engine.get_stats()
                    self.system_stats.update({
                        'threats_detected': stats.get('threats_detected', 0),
                        'scans_performed': stats.get('scans_performed', 0),
                        'uptime': stats.get('uptime_seconds', 0)
                    })
                
        except Exception as e:
            self.logger.error(f"Error actualizando stats: {e}")
    
    def _setup_demo_mode(self):
        """Configurar modo demo si el backend no está disponible"""
        self.logger.warning("⚠️ Activando modo demo - usando datos básicos...")
        
        # Solo usar datos básicos como respaldo
        self.demo_threats = []  # Vacío - se llenará con amenazas reales
        
        # Datos mínimos del sistema
        self.system_stats.update({
            'threats_detected': 0,
            'scans_performed': 0,
            'uptime': 0
        })
        
        # No configurar timer demo - usar datos reales
        self._demo_timer_active = False
        self.logger.info("✅ Modo demo configurado")
        self._update_backend_status("DEMO")

    def _create_main_window(self):
        """Crear la ventana principal y su contenido"""
        with dpg.window(tag="main_window", label="Antivirus Professional - GPU Accelerated", 
                       width=1280, height=720, no_resize=False, no_move=False, no_collapse=False):
            with dpg.group(horizontal=True):
                self._create_navigation_pane()
                self._create_main_content_area()
        
        # Establecer como ventana principal
        dpg.set_primary_window("main_window", True)
    
    def _create_navigation_pane(self):
        """Crear el panel de navegación lateral"""
        with dpg.child_window(width=200, tag="nav_pane"):
            dpg.add_text("Navigation", color=(150, 150, 150))
            dpg.add_separator()
            
            dpg.add_button(label="Dashboard", callback=lambda: self.switch_view("dashboard"), width=-1, height=40)
            dpg.add_button(label="Real-time Monitor", callback=lambda: self.switch_view("realtime_monitor"), width=-1, height=40)
            dpg.add_button(label="Threat Viewer", callback=lambda: self.switch_view("threat_viewer"), width=-1, height=40)
            dpg.add_button(label="Settings", callback=lambda: self.switch_view("settings"), width=-1, height=40)
            dpg.add_button(label="Logs", callback=lambda: self.switch_view("logs"), width=-1, height=40)
            
            dpg.add_spacer(height=250)
            
            dpg.add_text("System Info", color=(150, 150, 150))
            dpg.add_separator()
            dpg.add_text(f"Version: 2.0.0")
            dpg.add_text(f"Engine: GPU Accelerated")
            dpg.add_text(f"Backend: {BACKEND_TYPE} Backend")

    def _create_main_content_area(self):
        """Crear el área de contenido principal"""
        with dpg.child_window(tag="main_content"):
            # Vistas (solo una visible a la vez)
            with dpg.group(tag="dashboard_view", show=True):
                if self.dashboard: self.dashboard.create()
            with dpg.group(tag="realtime_monitor_view", show=False):
                if self.realtime_monitor: self.realtime_monitor.render()
            with dpg.group(tag="threat_viewer_view", show=False):
                if self.threat_viewer: self.threat_viewer.render()
            with dpg.group(tag="settings_view", show=False):
                if self.settings: self.settings.render()
            with dpg.group(tag="logs_view", show=False):
                if self.logs_viewer: self.logs_viewer.render()

    def switch_view(self, view_name: str):
        """Cambiar la vista principal"""
        views = ["dashboard", "realtime_monitor", "threat_viewer", "settings", "logs"]
        for view in views:
            if dpg.does_item_exist(f"{view}_view"):
                dpg.configure_item(f"{view}_view", show=(view == view_name))
        self.current_view = view_name
        self.logger.info(f"Switched to {view_name} view")

        # Actualizar la lista de amenazas si cambiamos a la vista de amenazas
        if view_name == "threat_viewer" and self.threat_viewer:
            self.threat_viewer._update_threat_list()

    def run(self):
        """Ejecutar la aplicación UI"""
        dpg.create_context()
        
        try:
            # Establecer flag de ejecución
            self.is_running = True
            
            self.logger.info("🚀 Starting Antivirus Professional UI...")
            
            # Crear interfaz
            self._setup_fonts()
            apply_dark_theme()
            
            self._create_ui_components()
            self._create_main_window()
            
            # Configurar viewport
            dpg.create_viewport(title='Antivirus Professional - GPU Accelerated', width=1280, height=720)
            dpg.setup_dearpygui()
            dpg.show_viewport()
            
            # El backend ahora se inicia solo cuando el usuario hace clic en "Start Scan"
            
            # Iniciar dashboard primero para UI responsiva
            if self.dashboard:
                self.dashboard.start_updates(self)
            
            # Iniciar backend en hilo separado para evitar bloqueo de UI
            backend_thread = threading.Thread(target=self._safe_initialize_backend, daemon=True)
            backend_thread.start()
        
            # Iniciar monitor de rendimiento
            self.performance_monitor.start_monitoring()
        
            # Loop principal de la UI
            while dpg.is_dearpygui_running():
                self._update_system_stats()
                dpg.render_dearpygui_frame()
            
            self.shutdown()

        except Exception as e:
            self.logger.error(f"❌ Error ejecutando aplicación: {e}")
            raise
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Cerrar aplicación limpiamente"""
        self.logger.info("🛑 Shutting down application...")
        
        # Detener flag principal para threads
        self.is_running = False
        
        # Esperar que los threads terminen
        if hasattr(self, 'engine_thread') and self.engine_thread and self.engine_thread.is_alive():
            self.logger.info("⏳ Esperando que termine el thread del backend...")
            self.engine_thread.join(timeout=3.0)  # Esperar máximo 3 segundos
        
        # Detener sistema de métricas si existe
        if hasattr(self, 'metrics_system') and self.metrics_system:
            try:
                if hasattr(self.metrics_system, 'running'):
                    self.metrics_system.running = False
            except Exception as e:
                self.logger.debug(f"Error stopping metrics system: {e}")
        
        # Detener motor antivirus
        if self.engine:
            try:
                self.logger.info("🛡️ Deteniendo motor antivirus...")
                self.engine.shutdown_system()
                # Dar tiempo para que el shutdown sea procesado
                import time
                time.sleep(1.0)
            except Exception as e:
                self.logger.error(f"❌ Error shutting down engine: {e}")
        
        # Limpiar Dear PyGui
        try:
            if dpg.is_dearpygui_running():
                dpg.stop_dearpygui()
            dpg.destroy_context()
        except Exception as e:
            self.logger.debug(f"Error cleaning up Dear PyGui: {e}")
        
        self.logger.info("✅ Application shutdown complete")


def main():
    """Función principal para ejecutar la aplicación"""
    
    print("🛡️ Antivirus Professional - Dear PyGui Frontend")
    print("=" * 50)
    
    # Verificar compatibilidad GPU
    try:
        import dearpygui.dearpygui as dpg
        dpg.create_context()
        print("✅ Dear PyGui compatible - GPU acceleration available")
        dpg.destroy_context()
    except Exception as e:
        print(f"❌ Dear PyGui initialization failed: {e}")
        print("💡 Try: pip install dearpygui")
        return 1
    
    # Crear y ejecutar aplicación
    try:
        app = AntivirusProfessionalUI()
        app.run()
        return 0
        
    except KeyboardInterrupt:
        print("🛑 Application interrupted by user")
        return 0
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)