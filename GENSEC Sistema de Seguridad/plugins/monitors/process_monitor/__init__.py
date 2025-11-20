"""
Plugin Process Monitor - Sistema de Monitoreo de Procesos
========================================================

Implementación de Plugin para monitoreo avanzado de comportamiento de procesos con
detección de patrones sospechosos, análisis de actividad y clasificación de amenazas.

Características:
- Monitoreo en tiempo real de procesos del sistema
- Detección de patrones de keyloggers y malware
- Análisis de comportamiento y uso de recursos
- Sistema de whitelist y terminación segura
- Integración completa con Event Bus y Registry

Design Patterns Implementados:
- Template Method: Para estructura de plugin base
- Observer: Mediante Event Bus para comunicación
- Strategy: Para diferentes estrategias de análisis
- Chain of Responsibility: Para procesamiento de eventos

Autor: Unified Antivirus Architecture
Versión: 3.1.0
Fecha: 2024-12-20
"""

import logging
import threading
import time
import psutil
import os
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable, Any
from collections import deque, defaultdict
import json

# Importar infraestructura del core
from core.base_plugin import BasePlugin, PluginInterface
from core.event_bus import Event

logger = logging.getLogger(__name__)


class ProcessBehaviorAnalyzer:
    """Analizador especializado para comportamiento de procesos"""

    def __init__(self, config: Dict):
        self.config = config

        # Patrones de detección
        self.suspicious_process_names = config.get(
            "suspicious_process_names",
            [
                "keylogger",
                "spyware",
                "stealer",
                "hack",
                "spy",
                "capture",
                "monitor",
                "logger",
                "recorder",
                "backdoor",
            ],
        )

        self.suspicious_file_patterns = config.get(
            "suspicious_file_patterns",
            [
                "keylog",
                "capture",
                "password",
                "credential",
                "spy",
                "hack",
                "stealer",
                "monitor",
                ".log",
                ".txt",
                "dump",
            ],
        )

        self.system_processes_whitelist = set(
            config.get(
                "system_processes_whitelist",
                [
                    "system",
                    "svchost.exe",
                    "explorer.exe",
                    "winlogon.exe",
                    "csrss.exe",
                    "wininit.exe",
                    "services.exe",
                    "lsass.exe",
                ],
            )
        )

        # Lista blanca personalizada
        self.whitelist_processes = set(config.get("whitelist_processes", []))
        self.trusted_directories = set(
            config.get(
                "trusted_directories",
                [
                    os.path.expandvars("%ProgramFiles%"),
                    os.path.expandvars("%ProgramFiles(x86)%"),
                    os.path.expandvars("%Windows%\\System32"),
                ],
            )
        )

        logger.info("[ANALYZER] Process Behavior Analyzer inicializado")

    def analyze_process(self, proc) -> Dict[str, Any]:
        """Análisis completo de un proceso"""
        try:
            return self._extract_process_info(proc)
        except Exception as e:
            logger.debug(f"Error analizando proceso {proc.pid}: {e}")
            return {}

    def _extract_process_info(self, proc) -> Dict[str, Any]:
        """Extrae información detallada de un proceso"""
        info = {}

        try:
            # Información básica
            info.update(
                {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "create_time": proc.create_time(),
                    "status": proc.status(),
                }
            )

            # Información extendida (con manejo de errores)
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["exe"] = "unknown"

            try:
                cmdline = proc.cmdline()
                info["cmdline"] = (
                    " ".join(cmdline[:5]) if cmdline else ""
                )  # Limitar longitud
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["cmdline"] = ""

            try:
                info["username"] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["username"] = "unknown"

            # Información de memoria y CPU
            try:
                memory_info = proc.memory_info()
                info.update(
                    {
                        "memory_rss": memory_info.rss,
                        "memory_vms": memory_info.vms,
                        "memory_percent": proc.memory_percent(),
                        "cpu_percent": proc.cpu_percent(),
                        "num_threads": proc.num_threads(),
                    }
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info.update(
                    {
                        "memory_rss": 0,
                        "memory_vms": 0,
                        "memory_percent": 0.0,
                        "cpu_percent": 0.0,
                        "num_threads": 0,
                    }
                )

            # Archivos abiertos (limitado para rendimiento)
            try:
                open_files = proc.open_files()
                info["open_files"] = [f.path for f in open_files[:5]]  # Solo primeros 5
                info["open_files_count"] = len(open_files)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["open_files"] = []
                info["open_files_count"] = 0

            # Conexiones de red
            try:
                connections = proc.connections()
                info["network_connections"] = len(connections)
                info["external_connections"] = len(
                    [
                        c
                        for c in connections
                        if c.raddr and not self._is_local_ip(c.raddr.ip)
                    ]
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info["network_connections"] = 0
                info["external_connections"] = 0

            # Análisis de comportamiento y riesgo
            info.update(self._analyze_process_behavior(info))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.debug(f"Error accediendo a proceso: {e}")
            info["error"] = str(e)

        return info

    def _analyze_process_behavior(self, proc_info: Dict) -> Dict[str, Any]:
        """Analiza el comportamiento del proceso para detectar patrones sospechosos"""
        behaviors = []
        risk_score = 0.0
        threat_indicators = []

        name = proc_info.get("name", "").lower()
        exe = proc_info.get("exe", "").lower()
        cmdline = proc_info.get("cmdline", "").lower()

        # 1. Verificar nombre sospechoso
        for suspicious_name in self.suspicious_process_names:
            if suspicious_name in name or suspicious_name in exe:
                behaviors.append("suspicious_name")
                threat_indicators.append("suspicious_process_name")
                risk_score += 0.8
                break

        # 2. Verificar archivos abiertos sospechosos
        open_files = proc_info.get("open_files", [])
        suspicious_file_access = False
        for file_path in open_files:
            file_path_lower = file_path.lower()
            for pattern in self.suspicious_file_patterns:
                if pattern in file_path_lower:
                    suspicious_file_access = True
                    break
            if suspicious_file_access:
                break

        if suspicious_file_access:
            behaviors.append("suspicious_file_access")
            threat_indicators.append("accessing_suspicious_files")
            risk_score += 0.3

        # 3. Verificar conexiones externas sospechosas
        external_connections = proc_info.get("external_connections", 0)
        if external_connections > 0 and not self._is_whitelisted_process(name):
            behaviors.append("external_network_access")
            threat_indicators.append("external_network_connections")
            risk_score += 0.2 * min(external_connections, 5)

        # 4. Verificar patrones específicos de keylogger
        keylogger_indicators = [
            "hook" in cmdline,
            "keyboard" in cmdline or "key" in cmdline,
            "capture" in cmdline,
            "log" in cmdline and "key" in cmdline,
            proc_info.get("open_files_count", 0) > 20,  # Muchos archivos abiertos
            (
                proc_info.get("memory_percent", 0) < 1.0 and external_connections > 0
            ),  # Bajo uso de memoria pero con red
            proc_info.get("num_threads", 0) > 10,  # Muchos hilos
        ]

        keylogger_score = sum(keylogger_indicators)
        if keylogger_score >= 2:
            behaviors.append("keylogger_pattern")
            threat_indicators.append("keylogger_behavior_pattern")
            risk_score += 0.6 + (keylogger_score * 0.1)

        # 5. Verificar proceso potencialmente oculto
        username = proc_info.get("username", "").lower()
        if (
            username not in ["system", "local service", "network service"]
            and "explorer" not in name
        ):
            if proc_info.get("memory_percent", 0) > 0 and external_connections > 0:
                behaviors.append("potentially_hidden")
                threat_indicators.append("hidden_process_with_network")
                risk_score += 0.1

        # 6. Verificar alta utilización de recursos sin justificación
        high_resource_usage = (
            proc_info.get("cpu_percent", 0) > 50
            or proc_info.get("memory_percent", 0) > 10
        )
        if high_resource_usage and len(behaviors) > 0:
            behaviors.append("high_resource_usage")
            threat_indicators.append("high_resource_consumption")
            risk_score += 0.2

        # 7. Verificar proceso sin ubicación conocida
        exe_path = proc_info.get("exe", "")
        if exe_path != "unknown" and not self._is_trusted_location(exe_path):
            behaviors.append("untrusted_location")
            threat_indicators.append("executing_from_untrusted_location")
            risk_score += 0.3

        # Normalizar score de riesgo
        risk_score = min(risk_score, 1.0)

        # Clasificar severidad
        severity = self._calculate_severity(risk_score)

        return {
            "behaviors": behaviors,
            "threat_indicators": threat_indicators,
            "risk_score": risk_score,
            "severity": severity,
            "analysis_timestamp": datetime.now().isoformat(),
        }

    def _is_local_ip(self, ip: str) -> bool:
        """Verifica si una IP es local/privada"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except Exception:
            return False

    def _is_whitelisted_process(self, process_name: str) -> bool:
        """Verifica si un proceso está en la lista blanca del sistema"""
        return process_name.lower() in self.system_processes_whitelist

    def _is_trusted_location(self, exe_path: str) -> bool:
        """Verifica si el ejecutable está en una ubicación de confianza"""
        if not exe_path or exe_path == "unknown":
            return False

        exe_path_lower = exe_path.lower()

        # Verificar directorios de confianza
        for trusted_dir in self.trusted_directories:
            trusted_dir_lower = trusted_dir.lower()
            if exe_path_lower.startswith(trusted_dir_lower):
                return True

        return False

    def _calculate_severity(self, risk_score: float) -> str:
        """Calcula la severidad basada en el score de riesgo"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "info"

    def is_suspicious_process(self, proc_info: Dict) -> bool:
        """Determina si un proceso es sospechoso basado en múltiples criterios"""
        if not proc_info:
            return False

        risk_score = proc_info.get("risk_score", 0.0)
        behaviors = proc_info.get("behaviors", [])
        threat_indicators = proc_info.get("threat_indicators", [])

        # Criterios de sospecha múltiples
        suspicious_criteria = [
            risk_score >= 0.7,
            "keylogger_pattern" in behaviors,
            "suspicious_name" in behaviors,
            len(threat_indicators) >= 3,
            (
                "external_network_access" in behaviors
                and "suspicious_file_access" in behaviors
            ),
        ]

        return any(suspicious_criteria)

    def detect_suspicious_changes(
        self, prev_info: Dict, current_info: Dict
    ) -> List[str]:
        """Detecta cambios sospechosos en un proceso entre escaneos"""
        changes = []

        try:
            # Incremento súbito en conexiones de red
            prev_connections = prev_info.get("external_connections", 0)
            current_connections = current_info.get("external_connections", 0)

            if current_connections > prev_connections + 3:
                changes.append("sudden_network_increase")

            # Incremento súbito en archivos abiertos
            prev_files = prev_info.get("open_files_count", 0)
            current_files = current_info.get("open_files_count", 0)

            if current_files > prev_files + 10:
                changes.append("sudden_file_access_increase")

            # Cambio en comportamientos críticos
            prev_behaviors = set(prev_info.get("behaviors", []))
            current_behaviors = set(current_info.get("behaviors", []))

            new_behaviors = current_behaviors - prev_behaviors
            if "keylogger_pattern" in new_behaviors:
                changes.append("new_keylogger_behavior")

            if "suspicious_file_access" in new_behaviors:
                changes.append("new_suspicious_file_activity")

            # Incremento significativo en uso de CPU
            prev_cpu = prev_info.get("cpu_percent", 0)
            current_cpu = current_info.get("cpu_percent", 0)

            if current_cpu > prev_cpu + 30:  # Incremento de 30% o más
                changes.append("sudden_cpu_spike")

        except Exception as e:
            logger.debug(f"Error detectando cambios: {e}")

        return changes


class ProcessMonitorPlugin(BasePlugin, PluginInterface):
    """
    Plugin de Monitoreo de Procesos - Implementación Template Method

    Proporciona monitoreo en tiempo real de procesos del sistema con:
    - Detección de patrones de keyloggers y malware
    - Análisis de comportamiento avanzado
    - Sistema de whitelist y terminación segura
    - Integración con Event Bus
    """

    def __init__(self):
        BasePlugin.__init__(self, "process_monitor", str(Path(__file__).parent))
        PluginInterface.__init__(self)
        self.plugin_type = "monitor"
        self.name = "process_monitor"
        self.version = "3.1.0"
        self.description = (
            "Monitor avanzado de comportamiento de procesos con detección inteligente"
        )

        # Componentes especializados
        self.analyzer = None

        # Estado del monitoreo
        self.is_monitoring = False
        self.monitor_thread = None

        # Buffer de eventos y tracking
        self.process_data = deque(maxlen=500)
        self.tracked_processes = {}  # PID -> process_info
        self.process_history = defaultdict(list)  # Historial por PID
        self.suspicious_processes = set()

        # Estadísticas
        self.stats = {
            "processes_monitored": 0,
            "suspicious_processes_detected": 0,
            "keylogger_patterns": 0,
            "processes_terminated": 0,
            "events_processed": 0,
            "start_time": None,
            "last_scan": None,
        }

        logger.info("[PLUGIN] ProcessMonitorPlugin inicializado")

    # Template Method Pattern - Métodos base requeridos

    def initialize(self) -> bool:
        """Inicialización del plugin - Template Method Step 1"""
        try:
            logger.info(f"[INIT] Inicializando {self.name} v{self.version}")

            # Configuración por defecto
            self.config = self._get_default_config()

            # Inicializar componente analizador
            self.analyzer = ProcessBehaviorAnalyzer(self.config)

            logger.info("[INIT] ProcessMonitorPlugin inicializado correctamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error inicializando ProcessMonitorPlugin: {e}")
            return False

    def configure(self, config: Dict) -> bool:
        """Configuración del plugin - Template Method Step 2"""
        try:
            logger.info("[CONFIG] Configurando ProcessMonitorPlugin")

            # Mergear con configuración por defecto
            self.config.update(config)

            # Reconfigurar analizador
            if self.analyzer:
                self.analyzer = ProcessBehaviorAnalyzer(self.config)

            logger.info("[CONFIG] ProcessMonitorPlugin configurado exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error configurando ProcessMonitorPlugin: {e}")
            return False

    def start(self) -> bool:
        """Inicio del plugin - Template Method Step 3"""
        try:
            if self.is_monitoring:
                logger.warning("[WARNING] ProcessMonitorPlugin ya está ejecutándose")
                return True

            logger.info("[START] Iniciando ProcessMonitorPlugin")

            self.is_monitoring = True
            self.stats["start_time"] = datetime.now()

            # Obtener snapshot inicial de procesos
            self._initial_process_scan()

            # Iniciar hilo de monitoreo
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop, name="ProcessMonitorPlugin", daemon=True
            )
            self.monitor_thread.start()

            # Publicar evento de inicio
            self._publish_event(
                "plugin_started",
                {
                    "plugin_name": self.name,
                    "plugin_type": self.plugin_type,
                    "version": self.version,
                },
            )

            logger.info("[START] ProcessMonitorPlugin iniciado exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error iniciando ProcessMonitorPlugin: {e}")
            self.is_monitoring = False
            return False

    def stop(self) -> bool:
        """Detención del plugin - Template Method Step 4"""
        try:
            if not self.is_monitoring:
                logger.warning("[WARNING] ProcessMonitorPlugin no está ejecutándose")
                return True

            logger.info("[STOP] Deteniendo ProcessMonitorPlugin")

            self.is_monitoring = False

            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5.0)

            # Publicar evento de detención
            self._publish_event(
                "plugin_stopped",
                {
                    "plugin_name": self.name,
                    "plugin_type": self.plugin_type,
                    "stats": self.get_stats(),
                },
            )

            logger.info("[STOP] ProcessMonitorPlugin detenido exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error deteniendo ProcessMonitorPlugin: {e}")
            return False

    def cleanup(self) -> bool:
        """Limpieza del plugin - Template Method Step 5"""
        try:
            logger.info("[CLEANUP] Limpiando recursos de ProcessMonitorPlugin")

            # Asegurar que el monitoreo está detenido
            if self.is_monitoring:
                self.stop()

            # Limpiar buffers y estructuras
            self.process_data.clear()
            self.tracked_processes.clear()
            self.process_history.clear()
            self.suspicious_processes.clear()

            # Resetear estadísticas
            self.stats = {
                "processes_monitored": 0,
                "suspicious_processes_detected": 0,
                "keylogger_patterns": 0,
                "processes_terminated": 0,
                "events_processed": 0,
                "start_time": None,
                "last_scan": None,
            }

            logger.info("[CLEANUP] Limpieza completada")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error en limpieza: {e}")
            return False

    # Implementación específica del plugin

    def _get_default_config(self) -> Dict:
        """Configuración por defecto del plugin"""
        return {
            # Configuración de monitoreo
            "enabled": True,
            "scan_interval": 10,  # segundos entre escaneos
            "process_history_limit": 100,  # Máximo historial por proceso
            "enable_termination": False,  # Permitir terminación automática
            "real_time_analysis": True,
            # Patrones de detección
            "suspicious_process_names": [
                "keylogger",
                "spyware",
                "stealer",
                "hack",
                "spy",
                "capture",
                "monitor",
                "logger",
                "recorder",
                "backdoor",
                "trojan",
                "virus",
                "malware",
                "rootkit",
                "bot",
            ],
            "suspicious_file_patterns": [
                "keylog",
                "capture",
                "password",
                "credential",
                "spy",
                "hack",
                "stealer",
                "monitor",
                ".log",
                ".txt",
                "dump",
                "passwords",
                "login",
                "auth",
                "token",
            ],
            # Lista blanca del sistema
            "system_processes_whitelist": [
                "system",
                "svchost.exe",
                "explorer.exe",
                "winlogon.exe",
                "csrss.exe",
                "wininit.exe",
                "services.exe",
                "lsass.exe",
                "smss.exe",
                "spoolsv.exe",
                "dwm.exe",
                "taskhost.exe",
                "conhost.exe",
                "audiodg.exe",
                "wmiprvse.exe",
            ],
            # Procesos de confianza personalizados
            "whitelist_processes": [
                "chrome.exe",
                "firefox.exe",
                "notepad.exe",
                "calc.exe",
                "mspaint.exe",
                "winword.exe",
                "excel.exe",
                "powerpnt.exe",
                "code.exe",
                "devenv.exe",
                "python.exe",
                "java.exe",
            ],
            # Directorios de confianza
            "trusted_directories": [
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                "C:\\Users\\{username}\\AppData\\Local\\Programs",
            ],
            # Umbrales de detección
            "thresholds": {
                "cpu_threshold": 50.0,
                "memory_threshold": 10.0,
                "connections_threshold": 5,
                "files_threshold": 20,
                "risk_score_threshold": 0.6,
            },
            # Configuración de eventos
            "event_config": {
                "enable_detailed_events": True,
                "max_event_size": 1000,
                "include_process_details": True,
            },
        }

    def _initial_process_scan(self):
        """Realiza un escaneo inicial de procesos activos"""
        try:
            logger.info("[SCAN] Realizando escaneo inicial de procesos")

            initial_processes = {}
            process_count = 0

            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    process_info = self.analyzer.analyze_process(proc)
                    if process_info:
                        initial_processes[proc.pid] = process_info
                        process_count += 1

                        # Verificar si es sospechoso
                        if self.analyzer.is_suspicious_process(process_info):
                            self.suspicious_processes.add(proc.pid)
                            self._handle_suspicious_process(process_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            self.tracked_processes = initial_processes
            self.stats["processes_monitored"] = process_count

            logger.info(
                f"[SCAN] Escaneo inicial completado: {process_count} procesos encontrados"
            )

        except Exception as e:
            logger.error(f"[ERROR] Error en escaneo inicial: {e}")

    def _monitoring_loop(self):
        """Bucle principal de monitoreo"""
        logger.info("[MONITOR] Iniciando bucle de monitoreo de procesos")

        while self.is_monitoring:
            try:
                scan_start = time.time()

                # Realizar escaneo de procesos
                self._scan_processes()

                # Actualizar estadísticas
                self.stats["last_scan"] = datetime.now()
                self.stats["events_processed"] += 1

                # Calcular tiempo de escaneo y ajustar intervalo
                scan_duration = time.time() - scan_start
                sleep_time = max(
                    0, self.config.get("scan_interval", 10) - scan_duration
                )

                if sleep_time > 0:
                    time.sleep(sleep_time)

            except Exception as e:
                logger.error(f"[ERROR] Error en bucle de monitoreo: {e}")
                time.sleep(5)  # Pausa en caso de error

        logger.info("[MONITOR] Bucle de monitoreo finalizado")

    def _scan_processes(self):
        """Escanea procesos actuales y detecta cambios"""
        try:
            current_pids = set()
            new_processes = {}

            # Escanear procesos actuales
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    current_pids.add(proc.pid)

                    # Analizar proceso
                    process_info = self.analyzer.analyze_process(proc)
                    if not process_info:
                        continue

                    new_processes[proc.pid] = process_info

                    # Verificar si es un proceso nuevo
                    if proc.pid not in self.tracked_processes:
                        self._handle_new_process(process_info)
                    else:
                        # Verificar cambios en proceso existente
                        self._handle_existing_process(proc.pid, process_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Detectar procesos terminados
            terminated_pids = set(self.tracked_processes.keys()) - current_pids
            for pid in terminated_pids:
                self._handle_terminated_process(pid)

            # Actualizar tracking
            self.tracked_processes = new_processes
            self.stats["processes_monitored"] = len(new_processes)

        except Exception as e:
            logger.error(f"[ERROR] Error escaneando procesos: {e}")

    def _handle_new_process(self, process_info: Dict):
        """Maneja la detección de un nuevo proceso"""
        try:
            pid = process_info.get("pid")
            name = process_info.get("name", "unknown")

            logger.debug(f"[NEW] Nuevo proceso detectado: {name} (PID: {pid})")

            # Verificar si es sospechoso
            if self.analyzer.is_suspicious_process(process_info):
                self.suspicious_processes.add(pid)
                self._handle_suspicious_process(process_info)

            # Agregar al historial
            self.process_history[pid].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "event": "process_started",
                    "process_info": process_info,
                }
            )

            # Publicar evento
            if self.config.get("event_config", {}).get("enable_detailed_events", True):
                self._publish_event(
                    "new_process_detected",
                    {
                        "process_info": process_info,
                        "is_suspicious": pid in self.suspicious_processes,
                        "timestamp": datetime.now().isoformat(),
                    },
                )

        except Exception as e:
            logger.error(f"[ERROR] Error manejando nuevo proceso: {e}")

    def _handle_existing_process(self, pid: int, current_info: Dict):
        """Maneja cambios en un proceso existente"""
        try:
            previous_info = self.tracked_processes.get(pid, {})

            # Detectar cambios sospechosos
            suspicious_changes = self.analyzer.detect_suspicious_changes(
                previous_info, current_info
            )

            if suspicious_changes:
                logger.warning(
                    f"[CHANGE] Cambios sospechosos en proceso {pid}: {suspicious_changes}"
                )

                # Agregar al historial
                self.process_history[pid].append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event": "suspicious_changes",
                        "changes": suspicious_changes,
                        "process_info": current_info,
                    }
                )

                # Marcar como sospechoso si no lo estaba
                if pid not in self.suspicious_processes:
                    self.suspicious_processes.add(pid)
                    self._handle_suspicious_process(current_info)

                # Publicar evento de cambio
                self._publish_event(
                    "process_behavior_change",
                    {
                        "pid": pid,
                        "changes": suspicious_changes,
                        "process_info": current_info,
                        "timestamp": datetime.now().isoformat(),
                    },
                )

            # Verificar si ahora es sospechoso
            elif (
                self.analyzer.is_suspicious_process(current_info)
                and pid not in self.suspicious_processes
            ):
                self.suspicious_processes.add(pid)
                self._handle_suspicious_process(current_info)

        except Exception as e:
            logger.error(f"[ERROR] Error procesando cambios en proceso {pid}: {e}")

    def _handle_terminated_process(self, pid: int):
        """Maneja la terminación de un proceso"""
        try:
            process_info = self.tracked_processes.get(pid, {})
            name = process_info.get("name", "unknown")

            logger.debug(f"[TERMINATED] Proceso terminado: {name} (PID: {pid})")

            # Agregar al historial
            if pid in self.process_history:
                self.process_history[pid].append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "event": "process_terminated",
                        "final_process_info": process_info,
                    }
                )

            # Limpiar de procesos sospechosos
            if pid in self.suspicious_processes:
                self.suspicious_processes.remove(pid)

                # Publicar evento de terminación de proceso sospechoso
                self._publish_event(
                    "suspicious_process_terminated",
                    {
                        "pid": pid,
                        "process_info": process_info,
                        "timestamp": datetime.now().isoformat(),
                    },
                )

            # Limpiar historial viejo (mantener últimas entradas)
            if pid in self.process_history:
                history_limit = self.config.get("process_history_limit", 100)
                if len(self.process_history[pid]) > history_limit:
                    self.process_history[pid] = self.process_history[pid][
                        -history_limit:
                    ]

        except Exception as e:
            logger.error(f"[ERROR] Error manejando proceso terminado {pid}: {e}")

    def _handle_suspicious_process(self, process_info: Dict):
        """Maneja la detección de un proceso sospechoso"""
        try:
            pid = process_info.get("pid")
            name = process_info.get("name", "unknown")
            risk_score = process_info.get("risk_score", 0.0)
            severity = process_info.get("severity", "info")
            threat_indicators = process_info.get("threat_indicators", [])
            behaviors = process_info.get("behaviors", [])

            logger.warning(
                f"[SUSPICIOUS] Proceso sospechoso detectado: {name} (PID: {pid}) - Riesgo: {risk_score:.2f}"
            )

            # Actualizar estadísticas
            self.stats["suspicious_processes_detected"] += 1

            if "keylogger_pattern" in behaviors:
                self.stats["keylogger_patterns"] += 1

            # Crear evento de amenaza detallado
            threat_event = {
                "threat_type": "suspicious_process",
                "severity": severity,
                "process_info": {
                    "pid": pid,
                    "name": name,
                    "exe": process_info.get("exe", "unknown"),
                    "cmdline": process_info.get("cmdline", ""),
                    "username": process_info.get("username", "unknown"),
                    "risk_score": risk_score,
                },
                "threat_details": {
                    "behaviors": behaviors,
                    "threat_indicators": threat_indicators,
                    "detection_method": "behavioral_analysis",
                },
                "timestamp": datetime.now().isoformat(),
                "source_plugin": self.name,
            }

            # Agregar detalles específicos de keylogger si aplica
            if "keylogger_pattern" in behaviors:
                threat_event["threat_type"] = "potential_keylogger"
                threat_event["keylogger_analysis"] = {
                    "pattern_detected": True,
                    "confidence": min(risk_score + 0.2, 1.0),
                    "specific_indicators": [
                        indicator
                        for indicator in threat_indicators
                        if "key" in indicator.lower() or "capture" in indicator.lower()
                    ],
                }

            # Publicar evento de amenaza
            self._publish_event("threat_detected", threat_event)

            # Evaluar terminación automática si está habilitada
            if self.config.get("enable_termination", False):
                self._evaluate_process_termination(process_info)

            # Agregar al buffer de procesos sospechosos para análisis futuro
            self.process_data.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "suspicious_process",
                    "process_info": process_info,
                }
            )

        except Exception as e:
            logger.error(f"[ERROR] Error manejando proceso sospechoso: {e}")

    def _evaluate_process_termination(self, process_info: Dict):
        """Evalúa si un proceso debe ser terminado automáticamente"""
        try:
            pid = process_info.get("pid")
            name = process_info.get("name", "unknown")
            risk_score = process_info.get("risk_score", 0.0)
            behaviors = process_info.get("behaviors", [])

            # Criterios para terminación automática (muy estrictos)
            terminate_criteria = [
                risk_score >= 0.9,  # Riesgo muy alto
                "keylogger_pattern" in behaviors and risk_score >= 0.7,
                "suspicious_name" in behaviors
                and "external_network_access" in behaviors,
                len(process_info.get("threat_indicators", [])) >= 4,
            ]

            should_terminate = any(terminate_criteria)

            if should_terminate:
                success = self._terminate_process_safely(pid)
                if success:
                    logger.warning(
                        f"[TERMINATE] Proceso {name} (PID: {pid}) terminado automáticamente"
                    )
                    self.stats["processes_terminated"] += 1

                    # Publicar evento de terminación
                    self._publish_event(
                        "process_terminated",
                        {
                            "pid": pid,
                            "name": name,
                            "reason": "automatic_termination",
                            "risk_score": risk_score,
                            "termination_criteria": [
                                criteria
                                for i, criteria in enumerate(
                                    [
                                        "high_risk_score",
                                        "keylogger_pattern",
                                        "suspicious_with_network",
                                        "multiple_indicators",
                                    ]
                                )
                                if terminate_criteria[i]
                            ],
                            "timestamp": datetime.now().isoformat(),
                        },
                    )

        except Exception as e:
            logger.error(f"[ERROR] Error evaluando terminación de proceso: {e}")

    def _terminate_process_safely(self, pid: int) -> bool:
        """Termina un proceso de forma segura"""
        try:
            proc = psutil.Process(pid)

            # Verificar que no sea un proceso crítico del sistema
            name = proc.name().lower()
            if name in self.analyzer.system_processes_whitelist:
                logger.warning(
                    f"[WARNING] No se puede terminar proceso del sistema: {name}"
                )
                return False

            # Intentar terminación grácil primero
            proc.terminate()

            # Esperar terminación grácil
            try:
                proc.wait(timeout=5)
                return True
            except psutil.TimeoutExpired:
                # Forzar terminación si es necesario
                proc.kill()
                proc.wait(timeout=3)
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
            logger.error(f"[ERROR] Error terminando proceso {pid}: {e}")
            return False

    def _publish_event(self, event_type: str, event_data: Dict):
        """Publica eventos al Event Bus"""
        try:
            if hasattr(self, "event_bus") and self.event_bus:
                event = Event(
                    type=event_type,
                    source=self.name,
                    data=event_data,
                    timestamp=datetime.now(),
                )
                self.event_bus.publish(event)
        except Exception as e:
            logger.debug(f"[DEBUG] Error publicando evento: {e}")

    # Métodos de información y estadísticas

    def get_stats(self) -> Dict:
        """Obtiene estadísticas actuales del plugin"""
        stats = self.stats.copy()

        # Agregar información de tiempo de ejecución
        if stats.get("start_time"):
            uptime = datetime.now() - stats["start_time"]
            stats["uptime_seconds"] = uptime.total_seconds()
            stats["uptime_formatted"] = str(uptime).split(".")[0]  # Sin microsegundos

        # Agregar información del estado actual
        stats.update(
            {
                "is_monitoring": self.is_monitoring,
                "current_tracked_processes": len(self.tracked_processes),
                "current_suspicious_processes": len(self.suspicious_processes),
                "process_history_entries": sum(
                    len(history) for history in self.process_history.values()
                ),
                "plugin_status": "active" if self.is_monitoring else "inactive",
            }
        )

        return stats

    def get_monitored_processes(self) -> List[Dict]:
        """Obtiene lista de procesos monitoreados actualmente"""
        return list(self.tracked_processes.values())

    def get_suspicious_processes(self) -> List[Dict]:
        """Obtiene lista de procesos sospechosos detectados"""
        suspicious_list = []
        for pid in self.suspicious_processes:
            if pid in self.tracked_processes:
                suspicious_list.append(self.tracked_processes[pid])
        return suspicious_list

    def get_process_history(self, pid: Optional[int] = None) -> Dict:
        """Obtiene historial de procesos"""
        if pid is not None:
            return {str(pid): self.process_history.get(pid, [])}

        # Convertir PIDs a strings para serialización JSON
        return {str(pid): history for pid, history in self.process_history.items()}

    def force_scan(self) -> Dict:
        """Fuerza un escaneo inmediato y retorna resultados"""
        try:
            logger.info("[FORCE_SCAN] Ejecutando escaneo forzado")

            scan_start = time.time()
            initial_count = len(self.tracked_processes)

            # Ejecutar escaneo
            self._scan_processes()

            scan_duration = time.time() - scan_start
            final_count = len(self.tracked_processes)

            result = {
                "scan_completed": True,
                "scan_duration": round(scan_duration, 3),
                "processes_before": initial_count,
                "processes_after": final_count,
                "suspicious_processes": len(self.suspicious_processes),
                "timestamp": datetime.now().isoformat(),
            }

            logger.info(f"[FORCE_SCAN] Escaneo completado en {scan_duration:.3f}s")
            return result

        except Exception as e:
            logger.error(f"[ERROR] Error en escaneo forzado: {e}")
            return {
                "scan_completed": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def terminate_suspicious_process(self, pid: int) -> bool:
        """Termina manualmente un proceso sospechoso específico"""
        try:
            if pid not in self.suspicious_processes:
                logger.warning(
                    f"[WARNING] PID {pid} no está en la lista de procesos sospechosos"
                )
                return False

            success = self._terminate_process_safely(pid)
            if success:
                logger.info(f"[MANUAL_TERMINATE] Proceso {pid} terminado manualmente")
                self.stats["processes_terminated"] += 1

            return success

        except Exception as e:
            logger.error(f"[ERROR] Error terminando proceso {pid} manualmente: {e}")
            return False

    def update_whitelist(self, processes: List[str]) -> bool:
        """Actualiza la lista blanca de procesos"""
        try:
            self.config["whitelist_processes"].extend(processes)

            # Reconfigurar analizador
            if self.analyzer:
                self.analyzer = ProcessBehaviorAnalyzer(self.config)

            logger.info(
                f"[WHITELIST] Lista blanca actualizada con {len(processes)} procesos"
            )
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error actualizando whitelist: {e}")
            return False

    # Métodos requeridos por PluginInterface (Observer Pattern)

    def on_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Maneja eventos del event bus"""
        try:
            if event_type == "system_shutdown":
                logger.info("[EVENT] Recibido evento de shutdown del sistema")
                self.stop()

            elif event_type == "configuration_updated":
                logger.info("[EVENT] Recibida actualización de configuración")
                new_config = data.get("config", {})
                if "process_monitor" in new_config:
                    self.configure(new_config["process_monitor"])

            elif event_type == "threat_whitelist_update":
                logger.info("[EVENT] Recibida actualización de whitelist")
                new_processes = data.get("processes", [])
                if new_processes:
                    self.update_whitelist(new_processes)

            elif event_type == "force_process_scan":
                logger.info("[EVENT] Recibido comando de escaneo forzado")
                self.force_scan()

            else:
                logger.debug(f"[EVENT] Evento no manejado: {event_type}")

        except Exception as e:
            logger.error(f"[ERROR] Error manejando evento {event_type}: {e}")

    def publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publica eventos al event bus"""
        self._publish_event(event_type, data)

    def get_plugin_info(self) -> Dict[str, Any]:
        """Información específica del ProcessMonitorPlugin"""
        return {
            "name": self.name,
            "version": self.version,
            "type": self.plugin_type,
            "description": self.description,
            "status": "active" if self.is_monitoring else "inactive",
            "capabilities": [
                "process_behavior_analysis",
                "keylogger_detection",
                "suspicious_pattern_analysis",
                "process_termination",
                "whitelist_management",
                "real_time_monitoring",
                "threat_scoring",
                "behavioral_anomaly_detection",
            ],
            "stats": self.get_stats(),
            "config_summary": {
                "scan_interval": self.config.get("scan_interval", 10),
                "enable_termination": self.config.get("enable_termination", False),
                "suspicious_patterns": len(
                    self.config.get("suspicious_process_names", [])
                ),
                "whitelist_processes": len(self.config.get("whitelist_processes", [])),
                "risk_threshold": self.config.get("thresholds", {}).get(
                    "risk_score_threshold", 0.6
                ),
            },
        }


# Función de test para verificar funcionalidad
def test_process_monitor_plugin():
    """Función de test para ProcessMonitorPlugin"""
    print("=== TEST ProcessMonitorPlugin ===")

    try:
        # Crear instancia del plugin
        plugin = ProcessMonitorPlugin()
        print(f"✓ Plugin creado: {plugin.name} v{plugin.version}")

        # Inicializar
        if plugin.initialize():
            print("✓ Plugin inicializado")
        else:
            print("✗ Error en inicialización")
            return False

        # Configurar
        test_config = {
            "scan_interval": 5,
            "enable_termination": False,
            "real_time_analysis": True,
        }

        if plugin.configure(test_config):
            print("✓ Plugin configurado")
        else:
            print("✗ Error en configuración")
            return False

        # Iniciar monitoreo
        if plugin.start():
            print("✓ Monitoreo iniciado")

            # Esperar un poco para ver funcionamiento
            print("Monitoreando procesos por 10 segundos...")
            time.sleep(10)

            # Obtener estadísticas
            stats = plugin.get_stats()
            print(f"✓ Procesos monitoreados: {stats['processes_monitored']}")
            print(f"✓ Procesos sospechosos: {stats['suspicious_processes_detected']}")
            print(f"✓ Patrones keylogger: {stats['keylogger_patterns']}")

            # Obtener procesos sospechosos
            suspicious = plugin.get_suspicious_processes()
            if suspicious:
                print(f"⚠ Procesos sospechosos encontrados: {len(suspicious)}")
                for proc in suspicious[:3]:  # Mostrar primeros 3
                    print(
                        f"  - {proc.get('name')} (PID: {proc.get('pid')}, Risk: {proc.get('risk_score', 0):.2f})"
                    )

            # Forzar escaneo
            scan_result = plugin.force_scan()
            if scan_result.get("scan_completed"):
                print(
                    f"✓ Escaneo forzado completado en {scan_result['scan_duration']}s"
                )

        else:
            print("✗ Error iniciando monitoreo")
            return False

        # Detener
        if plugin.stop():
            print("✓ Monitoreo detenido")
        else:
            print("✗ Error deteniendo monitoreo")

        # Limpiar
        if plugin.cleanup():
            print("✓ Limpieza completada")
        else:
            print("✗ Error en limpieza")

        print("=== TEST COMPLETADO EXITOSAMENTE ===")
        return True

    except Exception as e:
        print(f"✗ Error en test: {e}")
        return False


if __name__ == "__main__":
    # Configurar logging básico para tests
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Ejecutar test
    test_process_monitor_plugin()
