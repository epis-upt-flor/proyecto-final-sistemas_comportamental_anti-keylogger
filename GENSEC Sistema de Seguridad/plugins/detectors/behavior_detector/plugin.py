"""
Behavior Detector Plugin
========================

Plugin de detección de keyloggers usando análisis heurístico de comportamiento.
Implementa múltiples patrones de diseño para integración con el sistema unificado.
"""

import logging
import asyncio
import threading
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
import json
from pathlib import Path
import psutil

# Importar componentes del core
import sys
from pathlib import Path

# Añadir el directorio raíz al sys.path si no está presente
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import DetectorInterface

# Importar componentes específicos del behavior detector
from .behavior_engine import BehaviorEngine
from .rule_engine import RuleEngine, RiskLevel
from .whitelist_manager import WhitelistManager

logger = logging.getLogger(__name__)


class BehaviorDetectorPlugin(BasePlugin, DetectorInterface):
    """
    Plugin detector de keyloggers usando análisis heurístico

    Patrones implementados:
    - Template Method: Hereda ciclo de vida de BasePlugin
    - Strategy: Múltiples estrategias de análisis heurístico
    - Observer: Recibe eventos del sistema y publica detecciones
    - Command: Comandos de análisis ejecutables
    """

    def __init__(self, config_path: str = None):
        """
        Inicializa el plugin Behavior Detector

        Args:
            config_path: Ruta al archivo de configuración
        """
        super().__init__(
            plugin_name="behavior_detector", plugin_path=str(Path(__file__).parent)
        )

        # Información del plugin
        self.name = "behavior_detector"
        self.version = "1.0.0"
        self.description = (
            "Detector de keyloggers usando análisis heurístico de comportamiento"
        )

        # Configuración
        self.config_path = config_path or str(Path(__file__).parent / "config.json")
        self.config = self._load_config()

        # Motor de comportamiento
        self.behavior_engine = None

        # Estado del detector
        self.is_running = False
        self.detection_thread = None
        self.detection_queue = None  # Se inicializará cuando sea necesario

        # Métricas
        self.detections_count = 0
        self.processed_events = 0
        self.last_detection_time = None

        # Lock para thread safety
        self._lock = threading.RLock()

        logger.info(f"[PLUGIN] {self.name} inicializado")

    def _load_config(self) -> Dict[str, Any]:
        """Carga la configuración del plugin"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                logger.info(f"Configuración cargada desde {self.config_path}")
                return config
            else:
                logger.warning(
                    f"Archivo de configuración no encontrado: {self.config_path}"
                )
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error cargando configuración: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna configuración por defecto"""
        return {
            "behavior_config": {
                "risk_threshold": 0.7,
                "enable_advanced_analysis": True,
                "max_concurrent_analysis": 5,
                "analysis_timeout": 30,
            },
            "rules_config": {
                "enable_keyboard_rules": True,
                "enable_network_rules": True,
                "enable_file_rules": True,
                "enable_process_rules": True,
            },
            "whitelist_config": {
                "enable_process_whitelist": True,
                "enable_file_whitelist": True,
                "auto_learn": False,
            },
        }

    # === Implementación de BasePlugin ===

    def initialize(self) -> bool:
        """Inicializa el comportamiento del plugin"""
        try:
            logger.info(f"Inicializando {self.name}...")

            # Inicializar motor de comportamiento
            self.behavior_engine = BehaviorEngine(self.config)

            # Configurar cola de detección si no existe
            if self.detection_queue is None:
                import queue

                self.detection_queue = queue.Queue()

            logger.info(f"✅ {self.name} inicializado correctamente")
            return True

        except Exception as e:
            logger.error(f"❌ Error inicializando {self.name}: {e}")
            return False

    def start(self) -> bool:
        """Inicia el detector de comportamiento"""
        try:
            if self.is_running:
                logger.warning(f"{self.name} ya está ejecutándose")
                return True

            logger.info(f"Iniciando {self.name}...")

            # Inicializar si no se ha hecho
            if self.behavior_engine is None:
                self.initialize()

            # Marcar como ejecutándose
            self.is_running = True

            # Iniciar hilo de detección
            self.detection_thread = threading.Thread(
                target=self._detection_worker,
                name=f"{self.name}_detection_worker",
                daemon=True,
            )
            self.detection_thread.start()

            logger.info(f"✅ {self.name} iniciado correctamente")
            return True

        except Exception as e:
            logger.error(f"❌ Error iniciando {self.name}: {e}")
            self.is_running = False
            return False

    def stop(self) -> bool:
        """Detiene el detector de comportamiento"""
        try:
            if not self.is_running:
                logger.warning(f"{self.name} no está ejecutándose")
                return True

            logger.info(f"Deteniendo {self.name}...")

            # Marcar como detenido
            self.is_running = False

            # Esperar a que termine el hilo
            if self.detection_thread and self.detection_thread.is_alive():
                self.detection_thread.join(timeout=5.0)

            logger.info(f"✅ {self.name} detenido correctamente")
            return True

        except Exception as e:
            logger.error(f"❌ Error deteniendo {self.name}: {e}")
            return False

    def cleanup(self) -> bool:
        """Limpia recursos del plugin"""
        try:
            logger.info(f"Limpiando recursos de {self.name}...")

            # Detener si está ejecutándose
            if self.is_running:
                self.stop()

            # Limpiar cola
            if self.detection_queue:
                while not self.detection_queue.empty():
                    try:
                        self.detection_queue.get_nowait()
                    except:
                        break

            logger.info(f"✅ Recursos de {self.name} limpiados")
            return True

        except Exception as e:
            logger.error(f"❌ Error limpiando {self.name}: {e}")
            return False

    # === Implementación de DetectorInterface ===

    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detecta amenazas usando análisis heurístico

        Args:
            data: Datos del sistema para analizar

        Returns:
            Lista de amenazas detectadas
        """
        try:
            if not self.behavior_engine:
                logger.warning("Motor de comportamiento no inicializado")
                return []

            # Analizar con el motor de comportamiento
            analysis_results = self.behavior_engine.analyze("behavior_detector", [data])

            # Si se detectaron amenazas, crear entradas
            threats = []
            for result in analysis_results:
                if result.get("threat_detected", False):
                    threat = {
                        "threat_id": f"behavior_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(threats)}",
                        "threat_type": result.get(
                            "threat_type", "behavioral_keylogger"
                        ),
                        "confidence_score": result.get("risk_score", 0.0),
                        "description": result.get(
                            "description",
                            "Comportamiento sospechoso detectado por análisis heurístico",
                        ),
                        "details": result.get("details", {}),
                        "mitigation": "Revisar proceso y comportamiento del sistema",
                    }
                    threats.append(threat)

            return threats

            return []

        except Exception as e:
            logger.error(f"Error detectando amenazas: {e}")
            return []

    def get_confidence_score(self) -> float:
        """
        Retorna el nivel de confianza de la última detección

        Returns:
            Score de 0.0 a 1.0
        """
        # Por ahora retornar un score fijo, en el futuro se puede calcular dinámicamente
        return 0.85

    def update_signatures(self) -> bool:
        """
        Actualiza las reglas de comportamiento

        Returns:
            True si se actualizaron correctamente
        """
        try:
            # En el futuro aquí se pueden cargar nuevas reglas
            logger.info("Reglas de comportamiento actualizadas")
            return True
        except Exception as e:
            logger.error(f"Error actualizando reglas: {e}")
            return False

    def get_detection_statistics(self) -> Dict[str, Any]:
        """
        Estadísticas de detección del plugin Behavior
        """
        return {
            "total_detections": self.detections_count,
            "processed_events": self.processed_events,
            "last_detection": (
                self.last_detection_time.isoformat()
                if self.last_detection_time
                else None
            ),
            "behavior_engine_loaded": self.behavior_engine is not None,
            "plugin_uptime": (
                datetime.now() - datetime.now()
            ).total_seconds(),  # Placeholder
            "confidence_threshold": 0.7,  # Configurado por defecto
        }

    def analyze_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analiza datos para detectar comportamientos sospechosos

        Args:
            data: Datos a analizar (eventos del sistema)

        Returns:
            Resultado del análisis con score y detalles
        """
        try:
            with self._lock:
                self.processed_events += 1

                if not self.behavior_engine:
                    logger.warning("Motor de comportamiento no inicializado")
                    return {
                        "threat_detected": False,
                        "confidence_score": 0.0,
                        "threat_type": "unknown",
                        "details": "Motor no inicializado",
                    }

                # Analizar con el motor de comportamiento
                result = self._analyze_behavior(data)

                # Si se detectó amenaza, incrementar contador
                if result.get("threat_detected", False):
                    self.detections_count += 1
                    self.last_detection_time = datetime.now()

                return result

        except Exception as e:
            logger.error(f"Error en análisis de datos: {e}")
            return {
                "threat_detected": False,
                "confidence_score": 0.0,
                "threat_type": "analysis_error",
                "details": f"Error: {str(e)}",
            }

    def _analyze_behavior(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza comportamiento usando el motor heurístico"""
        try:
            # Analizar con el motor de comportamiento
            analysis_results = self.behavior_engine.analyze("behavior_detector", [data])

            # Convertir resultado a formato estándar
            if analysis_results and len(analysis_results) > 0:
                analysis_result = analysis_results[0]  # Tomar el primer resultado
                return {
                    "threat_detected": analysis_result.get("threat_detected", False),
                    "confidence_score": analysis_result.get("risk_score", 0.0),
                    "threat_type": analysis_result.get("threat_type", "behavioral"),
                    "details": analysis_result.get("details", {}),
                }
            else:
                return {
                    "threat_detected": False,
                    "confidence_score": 0.0,
                    "threat_type": "behavioral",
                    "details": {"analysis_time": datetime.now().isoformat()},
                }

        except Exception as e:
            logger.error(f"Error en análisis heurístico: {e}")
            return {
                "threat_detected": False,
                "confidence_score": 0.0,
                "threat_type": "heuristic_error",
                "details": f"Error en análisis: {str(e)}",
            }

    def _detection_worker(self):
        """Worker thread para monitoreo real de procesos"""
        logger.info(f"[BEHAVIOR_DETECTOR] Iniciando monitoreo real de procesos")

        # Obtener snapshot inicial de procesos
        tracked_processes = {}
        process_history = {}

        # Configuración de monitoreo INTELIGENTE
        scan_interval = 2.0
        
        # 🚫 PATRONES TONTOS ELIMINADOS - Usar sistema inteligente
        # 🧠 Solo usar análisis comportamental inteligente

        while self.is_running:
            try:
                current_pids = set()
                scan_time = datetime.now()

                # Escanear procesos activos
                for proc in psutil.process_iter(
                    [
                        "pid",
                        "name",
                        "exe",
                        "cmdline",
                        "create_time",
                        "memory_info",
                        "cpu_percent",
                    ]
                ):
                    try:
                        proc_info = proc.info
                        pid = proc_info["pid"]
                        current_pids.add(pid)

                        # Extraer información del proceso
                        process_data = {
                            "pid": pid,
                            "name": proc_info["name"],
                            "exe": proc_info.get("exe", "unknown"),
                            "cmdline": " ".join(proc_info.get("cmdline", []) or []),
                            "create_time": proc_info["create_time"],
                            "memory_rss": (
                                proc_info["memory_info"].rss
                                if proc_info.get("memory_info")
                                else 0
                            ),
                            "cpu_percent": proc_info.get("cpu_percent", 0),
                            "scan_time": scan_time,
                        }

                        # Proceso nuevo
                        if pid not in tracked_processes:
                            tracked_processes[pid] = process_data
                            process_history[pid] = []

                            # 🧠 Análisis inteligente (sin patrones tontos)
                            if self._analyze_suspicious_process(process_data):
                                self._trigger_detection(
                                    "suspicious_new_process", process_data
                                )

                        else:
                            # Proceso existente - verificar cambios
                            prev_data = tracked_processes[pid]
                            tracked_processes[pid] = process_data

                            # Agregar al historial
                            process_history[pid].append(process_data)
                            if len(process_history[pid]) > 10:
                                process_history[pid].pop(0)

                            # Detectar comportamiento sospechoso
                            if self._detect_suspicious_behavior(
                                prev_data, process_data
                            ):
                                self._trigger_detection(
                                    "suspicious_behavior_change", process_data
                                )

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess,
                    ):
                        continue

                # Limpiar procesos terminados
                terminated_pids = set(tracked_processes.keys()) - current_pids
                for pid in terminated_pids:
                    if pid in tracked_processes:
                        del tracked_processes[pid]
                    if pid in process_history:
                        del process_history[pid]

                # Estadísticas
                self.processed_events += len(current_pids)

                time.sleep(scan_interval)

            except Exception as e:
                logger.error(f"[BEHAVIOR_DETECTOR] Error en monitoreo: {e}")
                time.sleep(5.0)

        logger.info(f"[BEHAVIOR_DETECTOR] Monitoreo de procesos terminado")

    def _analyze_suspicious_process(
        self, process_data: Dict
    ) -> bool:
        """🧠 Análisis INTELIGENTE de procesos - NO patrones obvios"""
        try:
            name = process_data.get("name", "") or ""
            exe = process_data.get("exe", "") or ""
            cmdline = process_data.get("cmdline", "") or ""
            
            # Validar que los strings no sean None antes de lower()
            name = name.lower() if name else ""
            exe = exe.lower() if exe else ""
            cmdline = cmdline.lower() if cmdline else ""

            # 🧠 ANÁLISIS INTELIGENTE usando behavior_engine
            if hasattr(self, 'behavior_engine') and self.behavior_engine:
                # Usar el sistema de análisis comportamental correcto
                process_list = [{
                    "process_info": {
                        "name": name,
                        "exe": exe,
                        "cmdline": cmdline,
                        "pid": process_data.get("pid", 0)
                    }
                }]
                
                threats = self.behavior_engine.analyze("process", process_list)
                
                if threats and len(threats) > 0:
                    threat = threats[0]
                    risk_score = threat.get("risk_score", 0)
                    detected_rules = threat.get("detected_rules", [])
                    logger.warning(f"[INTELLIGENT_DETECTION] Proceso sospechoso: {name} - Score: {risk_score:.2f} - Rules: {detected_rules}")
                    return True
            else:
                # 🚫 Fallback básico - SOLO para procesos extremadamente sospechosos
                logger.debug(f"[BASIC_ANALYSIS] Análisis básico para: {name}")
                # Solo detectar procesos realmente peligrosos (no obvios)

            # Verificar procesos ocultos o sin ruta (excluir procesos del sistema)
            system_processes = [
                "system",
                "registry",
                "memory compression",
                "system idle process",
                "dwm.exe",
                "csrss.exe",
                "wininit.exe",
                "winlogon.exe",
            ]
            if exe == "unknown" or not exe:
                if name not in system_processes and name:
                    logger.debug(f"[DETECTION] Proceso sin ruta: {name}")
                    return True

            # 🧠 Línea de comandos: análisis inteligente (no patrones obvios)
            # Solo detectar comandos extremadamente sospechosos y no obvios
            if self._analyze_command_line_intelligence(cmdline):
                return True

            return False

        except Exception as e:
            logger.debug(f"Omitiendo proceso con datos incompletos: {e}")
            return False

    def _analyze_command_line_intelligence(self, cmdline: str) -> bool:
        """🧠 Análisis inteligente de líneas de comando - NO patrones obvios"""
        try:
            if not cmdline or len(cmdline) < 5:
                return False
                
            # 🚫 NO buscar patrones obvios como "hook", "keyboard", "capture"
            # 🧠 Buscar comportamientos realmente sospechosos y no obvios
            
            # 1. Inyección de código sospechosa
            injection_indicators = [
                "createremotethread",
                "writeprocessmemory", 
                "setwindowshookex",
                "ntcreateuserprocess"
            ]
            
            # 2. Evasión de detección
            evasion_indicators = [
                "deleteself",
                "/c del",
                "schtasks /delete",
                "attrib +h +s",
                "powershell -windowstyle hidden"
            ]
            
            cmdline_lower = cmdline.lower()
            
            # Verificar indicadores realmente sospechosos (no obvios)
            for indicator in injection_indicators + evasion_indicators:
                if indicator in cmdline_lower:
                    logger.warning(f"[INTELLIGENT_CMDLINE] Comportamiento sospechoso: {cmdline}")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error en análisis inteligente de cmdline: {e}")
            return False

    def _detect_suspicious_behavior(self, prev_data: Dict, current_data: Dict) -> bool:
        """Detecta cambios sospechosos en el comportamiento"""
        try:
            # Verificar incremento súbito en uso de memoria
            prev_memory = prev_data.get("memory_rss", 0)
            current_memory = current_data.get("memory_rss", 0)

            if (
                current_memory > prev_memory * 2 and current_memory > 50 * 1024 * 1024
            ):  # >50MB y duplicado
                logger.warning(
                    f"[DETECTION] Incremento súbito de memoria en {current_data.get('name')}: {prev_memory} -> {current_memory}"
                )
                return True

            # Verificar uso elevado de CPU (excluir procesos del sistema)
            cpu_percent = current_data.get("cpu_percent", 0)
            process_name = current_data.get("name", "").lower()

            # Lista de procesos que pueden usar mucha CPU legítimamente
            legitimate_high_cpu = [
                "chrome.exe",
                "firefox.exe",
                "code.exe",
                "system idle process",
                "system",
                "registry",
                "dwm.exe",
                "conhost.exe",
                "svchost.exe",
            ]

            if cpu_percent > 80 and process_name not in legitimate_high_cpu:
                logger.warning(
                    f"[DETECTION] Uso elevado de CPU: {current_data.get('name')} - {cpu_percent}%"
                )
                return True

            return False

        except Exception as e:
            logger.error(f"Error detectando comportamiento sospechoso: {e}")
            return False

    def _trigger_detection(self, detection_type: str, process_data: Dict):
        """Dispara una detección y notifica al sistema"""
        try:
            self.detections_count += 1
            self.last_detection_time = datetime.now()

            # Crear evento de detección
            detection_event = {
                "plugin": self.name,
                "type": detection_type,
                "severity": "high" if "suspicious" in detection_type else "medium",
                "timestamp": self.last_detection_time.isoformat(),
                "process_info": {
                    "pid": process_data.get("pid"),
                    "name": process_data.get("name"),
                    "exe": process_data.get("exe"),
                    "cmdline": process_data.get("cmdline", "")[
                        :200
                    ],  # Limitar longitud
                    "memory_rss": process_data.get("memory_rss", 0),
                    "cpu_percent": process_data.get("cpu_percent", 0),
                },
                "description": f"Detección de {detection_type} en proceso {process_data.get('name')}",
            }

            # Publicar evento en el EventBus
            if hasattr(self, "event_bus") and self.event_bus:
                self.event_bus.publish("security_alert", detection_event)
                logger.info(
                    f"[ALERT] {detection_type}: {process_data.get('name')} (PID: {process_data.get('pid')})"
                )

            # Log de la detección
            logger.warning(
                f"[DETECTION] {detection_type}: {process_data.get('name')} - {detection_event['description']}"
            )

        except Exception as e:
            logger.error(f"Error disparando detección: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Retorna el estado actual del plugin"""
        return {
            "plugin_name": self.name,
            "version": self.version,
            "is_running": self.is_running,
            "processed_events": self.processed_events,
            "detections_count": self.detections_count,
            "last_detection": (
                self.last_detection_time.isoformat()
                if self.last_detection_time
                else None
            ),
            "behavior_engine_loaded": self.behavior_engine is not None,
            "config_path": self.config_path,
        }

    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Información específica del plugin Behavior Detector
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": "detectors",
            "type": "behavior_detector",
            "capabilities": [
                "heuristic_analysis",
                "rule_engine",
                "whitelist_management",
            ],
            "dependencies": ["threading", "concurrent.futures"],
            "behavior_engine_loaded": self.behavior_engine is not None,
            "status": "active" if self.is_running else "inactive",
        }


def create_plugin(config_path: str = None) -> BehaviorDetectorPlugin:
    """
    Factory function para crear instancia del plugin

    Args:
        config_path: Ruta opcional al archivo de configuración

    Returns:
        Instancia del BehaviorDetectorPlugin
    """
    return BehaviorDetectorPlugin(config_path=config_path)


# Información del plugin para auto-discovery
PLUGIN_METADATA = {
    "name": "behavior_detector",
    "version": "1.0.0",
    "description": "Detector de keyloggers usando análisis heurístico de comportamiento",
    "category": "detectors",
    "interfaces": ["DetectorInterface"],
    "dependencies": ["behavior_engine", "rule_engine", "whitelist_manager"],
    "factory_function": create_plugin,
}
