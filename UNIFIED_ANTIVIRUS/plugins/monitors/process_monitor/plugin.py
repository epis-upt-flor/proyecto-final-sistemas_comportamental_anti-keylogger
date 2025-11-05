"""
Monitor de Procesos - Plugin para vigilancia de procesos del sistema
==================================================================

Monitorea procesos en tiempo real para detectar comportamientos sospechosos,
creación de nuevos procesos, uso anormal de recursos y patrones de keyloggers.
"""

import psutil
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

try:
    from interfaces import MonitorPluginInterface
    from plugins.base_plugin import BasePlugin
except ImportError:
    # Fallback para testing
    from abc import ABC, abstractmethod

    class MonitorPluginInterface(ABC):
        @abstractmethod
        def start_monitoring(self, target: Optional[str] = None) -> bool:
            pass

        @abstractmethod
        def stop_monitoring(self) -> bool:
            pass

        @abstractmethod
        def get_monitoring_status(self) -> Dict[str, Any]:
            pass

        @abstractmethod
        def get_monitoring_results(self) -> List[Dict[str, Any]]:
            pass

    class BasePlugin:
        def __init__(self, name: str, version: str):
            self.name = name
            self.version = version
            self.config = {}
            self.logger = None
            self.event_publisher = None

        def setup_logging(self):
            pass

        def load_config(self):
            pass

        def publish_event(self, event_type: str, data: Dict):
            pass

        def set_event_publisher(self, publisher):
            self.event_publisher = publisher


class ProcessMonitorPlugin(BasePlugin, MonitorPluginInterface):
    """Monitor de procesos del sistema con detección de anomalías"""

    def __init__(self, name: str, version: str):
        super().__init__(name, version)

        # Estado del monitor
        self.is_monitoring = False
        self.monitor_thread = None

        # Configuración de monitoreo
        self.monitor_config = {
            "update_interval": 2.0,  # segundos
            "cpu_threshold": 80.0,  # % CPU sospechoso
            "memory_threshold": 1024 * 1024 * 1024,  # 1GB memoria sospechosa
            "check_new_processes": True,
            "check_resource_usage": True,
            "check_suspicious_names": True,
        }

        # Lista de procesos conocidos
        self.known_processes = set()
        self.process_history = []

        # Patrones sospechosos
        self.suspicious_patterns = [
            "keylog",
            "keycap",
            "spyware",
            "trojan",
            "backdoor",
            "stealer",
            "logger",
            "capture",
            "hook",
            "inject",
        ]

        # Estadísticas
        self.stats = {
            "processes_monitored": 0,
            "suspicious_processes_detected": 0,
            "new_processes_detected": 0,
            "high_resource_usage_alerts": 0,
            "monitoring_start_time": None,
        }

    def initialize(self) -> bool:
        """Inicializa el monitor de procesos"""
        try:
            self.setup_logging()
            self.load_config()

            self.logger.info("Inicializando ProcessMonitor...")

            # Cargar configuración específica
            monitor_config = self.config.get("process_monitor", {})
            self.monitor_config.update(monitor_config)

            # Verificar psutil disponible
            if not self._check_psutil_available():
                self.logger.error("❌ psutil no está disponible")
                return False

            # Obtener snapshot inicial de procesos
            self._initialize_process_snapshot()

            self.logger.info("✅ ProcessMonitor inicializado correctamente")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error inicializando ProcessMonitor: {e}")
            return False

    def start(self) -> bool:
        """Inicia el monitoreo de procesos"""
        try:
            if self.is_monitoring:
                self.logger.warning("⚠️ ProcessMonitor ya está activo")
                return True

            self.logger.info("🚀 Iniciando monitoreo de procesos...")

            # Iniciar thread de monitoreo
            self.monitor_thread = threading.Thread(
                target=self._monitor_processes_loop, daemon=True
            )

            self.is_monitoring = True
            self.stats["monitoring_start_time"] = datetime.now()

            self.monitor_thread.start()

            # Notificar inicio
            self.publish_event(
                "monitor_started",
                {"monitor_type": "process", "timestamp": datetime.now().isoformat()},
            )

            self.logger.info("✅ ProcessMonitor iniciado exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error iniciando ProcessMonitor: {e}")
            self.is_monitoring = False
            return False

    def stop(self) -> bool:
        """Detiene el monitoreo de procesos"""
        try:
            if not self.is_monitoring:
                self.logger.warning("⚠️ ProcessMonitor no está activo")
                return True

            self.logger.info("🛑 Deteniendo monitoreo de procesos...")

            self.is_monitoring = False

            # Esperar que termine el thread
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5.0)

            # Notificar parada
            self.publish_event(
                "monitor_stopped",
                {
                    "monitor_type": "process",
                    "timestamp": datetime.now().isoformat(),
                    "stats": self.stats.copy(),
                },
            )

            self.logger.info("✅ ProcessMonitor detenido")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error deteniendo ProcessMonitor: {e}")
            return False

    # ================= MONITORPLUGININTERFACE =================
    def start_monitoring(self, target: Optional[str] = None) -> bool:
        """Inicia monitoreo (implementación de MonitorPluginInterface)"""
        return self.start()

    def stop_monitoring(self) -> bool:
        """Detiene monitoreo (implementación de MonitorPluginInterface)"""
        return self.stop()

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Obtiene estado del monitoreo"""
        return {
            "is_active": self.is_monitoring,
            "monitor_type": "process",
            "target": "system_processes",
            "uptime_seconds": self._get_uptime_seconds(),
            "stats": self.stats.copy(),
            "config": self.monitor_config.copy(),
        }

    def get_monitoring_results(self) -> List[Dict[str, Any]]:
        """Obtiene resultados del monitoreo"""
        return self.process_history.copy()

    # ================= CORE MONITORING LOGIC =================
    def _monitor_processes_loop(self):
        """Loop principal de monitoreo de procesos"""

        self.logger.info("📊 Iniciando loop de monitoreo de procesos")

        while self.is_monitoring:
            try:
                # Obtener procesos actuales
                current_processes = self._get_current_processes()

                # Detectar nuevos procesos
                if self.monitor_config["check_new_processes"]:
                    self._check_new_processes(current_processes)

                # Verificar uso de recursos
                if self.monitor_config["check_resource_usage"]:
                    self._check_resource_usage(current_processes)

                # Buscar nombres sospechosos
                if self.monitor_config["check_suspicious_names"]:
                    self._check_suspicious_names(current_processes)

                # Actualizar estadísticas
                self.stats["processes_monitored"] = len(current_processes)

                # Esperar próximo ciclo
                time.sleep(self.monitor_config["update_interval"])

            except Exception as e:
                self.logger.error(f"❌ Error en loop de monitoreo: {e}")
                time.sleep(1.0)  # Esperar un poco antes de reintentar

        self.logger.info("🏁 Loop de monitoreo terminado")

    def _get_current_processes(self) -> List[Dict[str, Any]]:
        """Obtiene lista de procesos actuales con información detallada"""

        processes = []

        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
                try:
                    # Información básica
                    process_info = proc.info

                    # Información adicional
                    process_info.update(
                        {
                            "cpu_percent": proc.cpu_percent(),
                            "memory_mb": proc.memory_info().rss / (1024 * 1024),
                            "status": proc.status(),
                            "username": (
                                proc.username()
                                if hasattr(proc, "username")
                                else "unknown"
                            ),
                        }
                    )

                    processes.append(process_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Proceso terminó o sin permisos
                    continue

        except Exception as e:
            self.logger.error(f"❌ Error obteniendo procesos: {e}")

        return processes

    def _check_new_processes(self, current_processes: List[Dict[str, Any]]):
        """Detecta nuevos procesos y evalúa si son sospechosos"""

        current_pids = {proc["pid"] for proc in current_processes}
        new_pids = current_pids - self.known_processes

        for pid in new_pids:
            # Encontrar información del proceso
            proc_info = next((p for p in current_processes if p["pid"] == pid), None)

            if proc_info:
                self.stats["new_processes_detected"] += 1

                # Crear evento de nuevo proceso
                event_data = {
                    "event_type": "new_process_detected",
                    "pid": pid,
                    "name": proc_info.get("name", "unknown"),
                    "exe_path": proc_info.get("exe", ""),
                    "create_time": proc_info.get("create_time", 0),
                    "timestamp": datetime.now().isoformat(),
                    "suspicious_score": self._calculate_suspicion_score(proc_info),
                }

                # Agregar a historial
                self.process_history.append(event_data)

                # Publicar evento
                self.publish_event("new_process_detected", event_data)

                self.logger.info(
                    f"🆕 Nuevo proceso detectado: {proc_info.get('name')} (PID: {pid})"
                )

        # Actualizar conjunto de procesos conocidos
        self.known_processes.update(current_pids)

    def _check_resource_usage(self, current_processes: List[Dict[str, Any]]):
        """Verifica uso anormal de recursos"""

        for proc in current_processes:
            cpu_usage = proc.get("cpu_percent", 0)
            memory_mb = proc.get("memory_mb", 0)

            # Verificar CPU alta
            if cpu_usage > self.monitor_config["cpu_threshold"]:
                self._alert_high_resource_usage("cpu", proc, cpu_usage)

            # Verificar memoria alta
            memory_bytes = memory_mb * 1024 * 1024
            if memory_bytes > self.monitor_config["memory_threshold"]:
                self._alert_high_resource_usage("memory", proc, memory_mb)

    def _check_suspicious_names(self, current_processes: List[Dict[str, Any]]):
        """Busca patrones sospechosos en nombres de procesos"""

        for proc in current_processes:
            name = proc.get("name", "").lower()
            exe_path = proc.get("exe", "").lower()

            # Verificar patrones sospechosos
            for pattern in self.suspicious_patterns:
                if pattern in name or pattern in exe_path:
                    self._alert_suspicious_process(proc, pattern)
                    break

    def _alert_high_resource_usage(
        self, resource_type: str, proc: Dict[str, Any], value: float
    ):
        """Alerta por uso alto de recursos"""

        self.stats["high_resource_usage_alerts"] += 1

        event_data = {
            "event_type": "high_resource_usage",
            "resource_type": resource_type,
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "value": value,
            "threshold": self.monitor_config.get(f"{resource_type}_threshold"),
            "timestamp": datetime.now().isoformat(),
        }

        self.process_history.append(event_data)
        self.publish_event("high_resource_usage_detected", event_data)

        self.logger.warning(
            f"⚠️ Alto uso de {resource_type}: {proc.get('name')} ({value:.1f})"
        )

    def _alert_suspicious_process(self, proc: Dict[str, Any], pattern: str):
        """Alerta por proceso con nombre sospechoso"""

        self.stats["suspicious_processes_detected"] += 1

        event_data = {
            "event_type": "suspicious_process_name",
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "exe_path": proc.get("exe"),
            "pattern_matched": pattern,
            "suspicion_score": self._calculate_suspicion_score(proc),
            "timestamp": datetime.now().isoformat(),
        }

        self.process_history.append(event_data)
        self.publish_event("suspicious_process_detected", event_data)

        self.logger.warning(
            f"🚨 Proceso sospechoso detectado: {proc.get('name')} (patrón: {pattern})"
        )

    def _calculate_suspicion_score(self, proc: Dict[str, Any]) -> float:
        """Calcula puntuación de sospecha para un proceso"""

        score = 0.0

        name = proc.get("name", "").lower()
        exe_path = proc.get("exe", "").lower()

        # Puntuación por patrones sospechosos
        for pattern in self.suspicious_patterns:
            if pattern in name:
                score += 0.3
            if pattern in exe_path:
                score += 0.2

        # Puntuación por ubicación sospechosa
        suspicious_locations = ["temp", "appdata", "users"]
        for location in suspicious_locations:
            if location in exe_path:
                score += 0.1

        # Puntuación por uso de recursos
        cpu_usage = proc.get("cpu_percent", 0)
        if cpu_usage > 50:
            score += 0.1

        return min(score, 1.0)

    # ================= UTILITY METHODS =================
    def _check_psutil_available(self) -> bool:
        """Verifica si psutil está disponible"""
        try:
            psutil.cpu_count()
            return True
        except Exception:
            return False

    def _initialize_process_snapshot(self):
        """Inicializa snapshot de procesos actuales"""
        try:
            current_processes = self._get_current_processes()
            self.known_processes = {proc["pid"] for proc in current_processes}
            self.logger.info(
                f"📊 Snapshot inicial: {len(self.known_processes)} procesos"
            )
        except Exception as e:
            self.logger.error(f"❌ Error en snapshot inicial: {e}")

    def _get_uptime_seconds(self) -> float:
        """Calcula tiempo de actividad en segundos"""
        if self.stats["monitoring_start_time"]:
            return (
                datetime.now() - self.stats["monitoring_start_time"]
            ).total_seconds()
        return 0.0

    def is_process_safe(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        🔍 TDD #3: Validación de procesos seguros para prevención de falsos positivos.

        IMPLEMENTACIÓN INTEGRADA desde TDD al ProcessMonitorPlugin real del antivirus.
        Sistema inteligente de whitelist/blacklist para evitar alertas innecesarias.

        Args:
            process_data: Diccionario con información del proceso:
                - name: Nombre del proceso
                - path: Ruta completa del ejecutable
                - digital_signature: Firma digital (opcional)

        Returns:
            Diccionario con resultado de la validación completa:
            {
                'is_safe': bool,
                'confidence': float (0.0-1.0),
                'threat_score': float (0.0-1.0),
                'category': str,
                'threat_indicators': list[str],
                'trust_factors': list[str],
                'requires_investigation': bool,
                'recommendation': str
            }
        """
        import re

        # Inicializar resultado
        result = {
            "is_safe": None,  # None = requiere investigación
            "confidence": 0.5,  # Neutral por defecto
            "threat_score": 0.5,  # Neutral por defecto
            "category": "unknown",
            "threat_indicators": [],
            "trust_factors": [],
            "requires_investigation": True,  # Por defecto requiere investigación
            "recommendation": "monitor",
        }

        process_name = process_data.get("name", "").lower()
        process_path = process_data.get("path", "").lower()
        digital_signature = process_data.get("digital_signature")
        signature_valid = process_data.get("signature_valid", False)

        # Configuración de procesos seguros desde config del antivirus
        safe_processes_config = self.config.get(
            "safe_processes",
            {
                "system_processes": [
                    "notepad.exe",
                    "calc.exe",
                    "mspaint.exe",
                    "explorer.exe",
                    "dwm.exe",
                    "winlogon.exe",
                    "csrss.exe",
                    "smss.exe",
                ],
                "browsers": [
                    "chrome.exe",
                    "firefox.exe",
                    "msedge.exe",
                    "opera.exe",
                    "brave.exe",
                    "safari.exe",
                    "iexplore.exe",
                ],
                "productivity": [
                    "winword.exe",
                    "excel.exe",
                    "powerpnt.exe",
                    "outlook.exe",
                    "notepad++.exe",
                    "code.exe",
                    "devenv.exe",
                ],
                "gaming": [
                    "steam.exe",
                    "discord.exe",
                    "spotify.exe",
                    "vlc.exe",
                    "obs64.exe",
                    "epicgameslauncher.exe",
                ],
            },
        )

        suspicious_processes_config = self.config.get(
            "suspicious_processes",
            {
                "obvious_malware": [
                    "keylogger.exe",
                    "stealer.exe",
                    "backdoor.exe",
                    "rootkit.exe",
                    "trojan.exe",
                    "virus.exe",
                ],
                "suspicious_patterns": [
                    r"^[a-f0-9]{8,}\.exe$",  # Nombres hexadecimales
                    r"^[0-9]+\.exe$",  # Solo números
                    r"^.{1,3}\.exe$",  # Muy cortos
                    r".*temp.*\.exe$",  # En carpeta temp
                ],
            },
        )

        trusted_locations = [
            loc.lower()
            for loc in self.config.get(
                "trusted_locations",
                [
                    "C:\\Windows\\System32\\",
                    "C:\\Windows\\",
                    "C:\\Program Files\\",
                    "C:\\Program Files (x86)\\",
                ],
            )
        ]

        # Variables para scoring
        confidence_score = 0.5
        threat_score = 0.5
        trust_factors = []
        threat_indicators = []
        category = "unknown"

        # ANÁLISIS 1: Procesos conocidos seguros
        all_safe = []
        category_mapping = {
            "system_processes": "system_process",
            "browsers": "browser",
            "productivity": "productivity",
            "gaming": "gaming",
        }

        for cat_name, processes in safe_processes_config.items():
            for proc in processes:
                all_safe.append(proc.lower())
                if process_name == proc.lower():
                    category = category_mapping.get(cat_name, cat_name)
                    confidence_score += 0.4
                    threat_score -= 0.4
                    trust_factors.append("known_safe_process")
                    break

        # ANÁLISIS 2: Procesos obviamente maliciosos
        malware_names = suspicious_processes_config.get("obvious_malware", [])
        for malware in malware_names:
            if process_name == malware.lower():
                category = "malware"
                confidence_score = 0.05
                threat_score = 0.95
                threat_indicators.append("obvious_malware")
                break

        # ANÁLISIS 3: Patrones sospechosos en nombres
        suspicious_patterns = suspicious_processes_config.get("suspicious_patterns", [])
        for pattern in suspicious_patterns:
            if re.match(pattern, process_name):
                threat_indicators.append("suspicious_naming_pattern")
                confidence_score -= 0.2
                threat_score += 0.2
                break

        # ANÁLISIS 4: Ubicación del proceso
        is_in_trusted_location = any(
            process_path.startswith(loc) for loc in trusted_locations
        )

        if is_in_trusted_location:
            trust_factors.append("trusted_location")
            confidence_score += 0.2
            threat_score -= 0.2
        else:
            # Proceso legítimo en ubicación sospechosa
            if process_name in all_safe:
                threat_indicators.append("suspicious_location")
                threat_indicators.append("impersonation_attempt")
                confidence_score -= 0.3
                threat_score += 0.3

        # ANÁLISIS 5: Firma digital
        trusted_publishers = [
            "microsoft corporation",
            "google llc",
            "adobe systems incorporated",
            "mozilla corporation",
            "apple inc.",
            "nvidia corporation",
        ]

        if digital_signature and signature_valid:
            trust_factors.append("trusted_signature")
            signature_lower = digital_signature.lower()

            if any(publisher in signature_lower for publisher in trusted_publishers):
                trust_factors.append("reputable_publisher")
                confidence_score += 0.3
                threat_score -= 0.3
            else:
                confidence_score += 0.1
                threat_score -= 0.1
        elif digital_signature is None or not signature_valid:
            # Sin firma o firma inválida
            confidence_score -= 0.1
            threat_score += 0.1

        # Normalizar scores con redondeo para evitar problemas de float
        confidence_score = round(max(0.0, min(1.0, confidence_score)), 10)
        threat_score = round(max(0.0, min(1.0, threat_score)), 10)

        # DECISIÓN FINAL
        result["confidence"] = confidence_score
        result["threat_score"] = threat_score
        result["category"] = category
        result["trust_factors"] = trust_factors
        result["threat_indicators"] = threat_indicators

        # Umbrales de decisión
        threshold = self.config.get("reputation_threshold", 0.8)

        if "obvious_malware" in threat_indicators:
            # Malware obvio - bloquear inmediatamente
            result["is_safe"] = False
            result["requires_investigation"] = False
            result["recommendation"] = "block"
        elif confidence_score >= 0.7 and threat_score <= 0.2:
            # Proceso altamente confiable
            result["is_safe"] = True
            result["requires_investigation"] = False
            result["recommendation"] = "allow"
        elif confidence_score <= 0.3 or threat_score >= 0.7:
            # Proceso peligroso
            result["is_safe"] = False
            result["requires_investigation"] = True
            result["recommendation"] = "quarantine"
        elif (
            "suspicious_location" in threat_indicators
            and "impersonation_attempt" in threat_indicators
        ):
            # Posible suplantación
            result["is_safe"] = False
            result["requires_investigation"] = True
            result["recommendation"] = "quarantine"
        else:
            # Proceso desconocido - requiere análisis
            result["is_safe"] = None
            result["requires_investigation"] = True
            result["recommendation"] = "monitor"

        # Log del análisis si es sospechoso
        if result["is_safe"] is False:
            self.logger.warning(
                f"[PROCESS_VALIDATION] Proceso peligroso detectado: {process_name} "
                f"(Score: {result['threat_score']:.2f}, Indicadores: {result['threat_indicators']})"
            )
        elif result["is_safe"] is True:
            self.logger.debug(
                f"[PROCESS_VALIDATION] Proceso seguro validado: {process_name} "
                f"(Confianza: {result['confidence']:.2f})"
            )

        return result
