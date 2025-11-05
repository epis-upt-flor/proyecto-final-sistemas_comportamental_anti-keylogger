"""
Monitor del Sistema de Archivos - Plugin para vigilancia de archivos
==================================================================

Monitorea cambios en el sistema de archivos para detectar creación de archivos
sospechosos, modificaciones no autorizadas y actividad de keyloggers.
"""

import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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


class FileSystemMonitorHandler(FileSystemEventHandler):
    """Handler personalizado para eventos del sistema de archivos"""

    def __init__(self, parent_monitor):
        super().__init__()
        self.parent = parent_monitor

    def on_created(self, event):
        if not event.is_directory:
            self.parent._handle_file_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.parent._handle_file_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.parent._handle_file_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.parent._handle_file_event("moved", event.dest_path, event.src_path)


class FileSystemMonitorPlugin(BasePlugin, MonitorPluginInterface):
    """Monitor del sistema de archivos con detección de actividad sospechosa"""

    def __init__(self, name: str, version: str):
        super().__init__(name, version)

        # Estado del monitor
        self.is_monitoring = False
        self.observer = None
        self.event_handler = None

        # Configuración de monitoreo
        self.monitor_config = {
            "watch_directories": [
                str(Path.home() / "Documents"),
                str(Path.home() / "Desktop"),
                str(Path.home() / "AppData" / "Roaming"),
                "C:\\Windows\\Temp",
                "C:\\Temp",
            ],
            "suspicious_extensions": [
                ".exe",
                ".dll",
                ".bat",
                ".cmd",
                ".scr",
                ".vbs",
                ".js",
                ".jar",
                ".com",
                ".pif",
                ".application",
                ".gadget",
            ],
            "keylogger_patterns": [
                "keylog",
                "keycap",
                "logger",
                "capture",
                "hook",
                "spy",
                "stealer",
                "backdoor",
                "trojan",
            ],
            "max_file_size_mb": 100,  # Archivos sospechosos por tamaño
            "track_file_hashes": True,
            "alert_threshold_events_per_minute": 50,
        }

        # Historial de eventos
        self.file_events = []
        self.file_hashes = {}

        # Estadísticas
        self.stats = {
            "files_monitored": 0,
            "suspicious_files_detected": 0,
            "file_events_total": 0,
            "directories_watched": 0,
            "monitoring_start_time": None,
        }

        # Control de eventos frecuentes
        self.recent_events = []

    def initialize(self) -> bool:
        """Inicializa el monitor del sistema de archivos"""
        try:
            self.setup_logging()
            self.load_config()

            if hasattr(self, "logger"):
                self.logger.info("Inicializando FileSystemMonitor...")

            # Cargar configuración específica
            fs_config = self.config.get("file_system_monitor", {})
            self.monitor_config.update(fs_config)

            # Verificar watchdog disponible
            if not self._check_watchdog_available():
                if hasattr(self, "logger"):
                    self.logger.error("❌ watchdog no está disponible")
                return False

            # Verificar directorios de monitoreo
            valid_dirs = self._validate_watch_directories()
            if not valid_dirs:
                if hasattr(self, "logger"):
                    self.logger.error("❌ No hay directorios válidos para monitorear")
                return False

            # Inicializar handler de eventos
            self.event_handler = FileSystemMonitorHandler(self)

            if hasattr(self, "logger"):
                self.logger.info("✅ FileSystemMonitor inicializado correctamente")
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error inicializando FileSystemMonitor: {e}")
            return False

    def start(self) -> bool:
        """Inicia el monitoreo del sistema de archivos"""
        try:
            if self.is_monitoring:
                if hasattr(self, "logger"):
                    self.logger.warning("⚠️ FileSystemMonitor ya está activo")
                return True

            if hasattr(self, "logger"):
                self.logger.info("🚀 Iniciando monitoreo del sistema de archivos...")

            # Crear observer
            self.observer = Observer()

            # Agregar directorios a monitorear
            watched_count = 0
            for directory in self.monitor_config["watch_directories"]:
                if os.path.exists(directory):
                    self.observer.schedule(
                        self.event_handler, directory, recursive=True
                    )
                    watched_count += 1

            # Iniciar observer
            self.observer.start()
            self.is_monitoring = True
            self.stats["directories_watched"] = watched_count
            self.stats["monitoring_start_time"] = datetime.now()

            # Notificar inicio
            if hasattr(self, "event_publisher") and self.event_publisher:
                self.publish_event(
                    "monitor_started",
                    {
                        "monitor_type": "filesystem",
                        "directories_watched": watched_count,
                        "timestamp": datetime.now().isoformat(),
                    },
                )

            if hasattr(self, "logger"):
                self.logger.info(
                    f"✅ FileSystemMonitor iniciado - {watched_count} directorios monitoreados"
                )
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error iniciando FileSystemMonitor: {e}")
            self.is_monitoring = False
            return False

    def stop(self) -> bool:
        """Detiene el monitoreo del sistema de archivos"""
        try:
            if not self.is_monitoring:
                if hasattr(self, "logger"):
                    self.logger.warning("⚠️ FileSystemMonitor no está activo")
                return True

            if hasattr(self, "logger"):
                self.logger.info("🛑 Deteniendo monitoreo del sistema de archivos...")

            # Detener observer
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5.0)

            self.is_monitoring = False

            # Notificar parada
            if hasattr(self, "event_publisher") and self.event_publisher:
                self.publish_event(
                    "monitor_stopped",
                    {
                        "monitor_type": "filesystem",
                        "timestamp": datetime.now().isoformat(),
                        "stats": self.stats.copy(),
                    },
                )

            if hasattr(self, "logger"):
                self.logger.info("✅ FileSystemMonitor detenido")
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error deteniendo FileSystemMonitor: {e}")
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
            "monitor_type": "filesystem",
            "target": "file_system",
            "uptime_seconds": self._get_uptime_seconds(),
            "stats": self.stats.copy(),
            "config": self.monitor_config.copy(),
        }

    def get_monitoring_results(self) -> List[Dict[str, Any]]:
        """Obtiene resultados del monitoreo"""
        return self.file_events.copy()

    # ================= CORE MONITORING LOGIC =================
    def _handle_file_event(self, event_type: str, file_path: str, old_path: str = None):
        """Maneja eventos del sistema de archivos"""

        try:
            # Actualizar estadísticas
            self.stats["file_events_total"] += 1

            # Controlar frecuencia de eventos
            if self._is_event_spam():
                return

            # Crear evento base
            event_data = {
                "event_type": event_type,
                "file_path": file_path,
                "timestamp": datetime.now().isoformat(),
                "suspicious_score": 0.0,
            }

            if old_path:
                event_data["old_path"] = old_path

            # Analizar archivo
            if event_type in ["created", "modified"]:
                self._analyze_file(file_path, event_data)

            # Verificar si es sospechoso
            if event_data["suspicious_score"] > 0.3:
                self.stats["suspicious_files_detected"] += 1
                self._alert_suspicious_file(event_data)

            # Agregar al historial
            self.file_events.append(event_data)

            # Mantener historial limitado
            if len(self.file_events) > 1000:
                self.file_events = self.file_events[-500:]

            # Publicar evento
            if hasattr(self, "event_publisher") and self.event_publisher:
                self.publish_event("file_system_event", event_data)

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error manejando evento de archivo: {e}")

    def _analyze_file(self, file_path: str, event_data: Dict[str, Any]):
        """Analiza archivo para detectar características sospechosas"""

        try:
            if not os.path.exists(file_path):
                return

            # Información del archivo
            file_stat = os.stat(file_path)
            file_size_mb = file_stat.st_size / (1024 * 1024)

            event_data["file_size_mb"] = file_size_mb
            event_data["file_extension"] = Path(file_path).suffix.lower()

            # Calcular hash si está habilitado
            if self.monitor_config["track_file_hashes"] and file_size_mb < 10:
                file_hash = self._calculate_file_hash(file_path)
                event_data["file_hash"] = file_hash

                # Verificar si es archivo duplicado sospechoso
                if file_hash in self.file_hashes:
                    event_data["suspicious_score"] += 0.2
                else:
                    self.file_hashes[file_hash] = file_path

            # Verificar extensión sospechosa
            if (
                event_data["file_extension"]
                in self.monitor_config["suspicious_extensions"]
            ):
                event_data["suspicious_score"] += 0.4

            # Verificar patrones de keylogger en nombre
            filename = os.path.basename(file_path).lower()
            for pattern in self.monitor_config["keylogger_patterns"]:
                if pattern in filename:
                    event_data["suspicious_score"] += 0.5
                    event_data["pattern_matched"] = pattern
                    break

            # Verificar tamaño sospechoso
            if file_size_mb > self.monitor_config["max_file_size_mb"]:
                event_data["suspicious_score"] += 0.2

            # Verificar ubicación sospechosa
            if any(
                suspicious_dir in file_path.lower()
                for suspicious_dir in ["temp", "tmp", "cache"]
            ):
                event_data["suspicious_score"] += 0.1

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error analizando archivo {file_path}: {e}")

    def _alert_suspicious_file(self, event_data: Dict[str, Any]):
        """Genera alerta por archivo sospechoso"""

        alert_data = {
            "alert_type": "suspicious_file_activity",
            "file_path": event_data["file_path"],
            "event_type": event_data["event_type"],
            "suspicious_score": event_data["suspicious_score"],
            "reasons": [],
            "timestamp": event_data["timestamp"],
        }

        # Agregar razones de sospecha
        if (
            event_data.get("file_extension")
            in self.monitor_config["suspicious_extensions"]
        ):
            alert_data["reasons"].append(
                f"Extensión sospechosa: {event_data['file_extension']}"
            )

        if "pattern_matched" in event_data:
            alert_data["reasons"].append(
                f"Patrón keylogger: {event_data['pattern_matched']}"
            )

        if event_data.get("file_size_mb", 0) > self.monitor_config["max_file_size_mb"]:
            alert_data["reasons"].append(
                f"Tamaño inusual: {event_data['file_size_mb']:.1f} MB"
            )

        # Publicar alerta
        if hasattr(self, "event_publisher") and self.event_publisher:
            self.publish_event("suspicious_file_detected", alert_data)

        if hasattr(self, "logger"):
            self.logger.warning(
                f"🚨 Archivo sospechoso: {event_data['file_path']} (score: {event_data['suspicious_score']:.2f})"
            )

    def _is_event_spam(self) -> bool:
        """Detecta si hay demasiados eventos por minuto (posible spam)"""

        now = datetime.now()

        # Limpiar eventos antiguos (más de 1 minuto)
        self.recent_events = [
            event_time
            for event_time in self.recent_events
            if (now - event_time).seconds < 60
        ]

        # Agregar evento actual
        self.recent_events.append(now)

        # Verificar threshold
        return (
            len(self.recent_events)
            > self.monitor_config["alert_threshold_events_per_minute"]
        )

    # ================= UTILITY METHODS =================
    def _check_watchdog_available(self) -> bool:
        """Verifica si watchdog está disponible"""
        try:
            from watchdog.observers import Observer

            return True
        except ImportError:
            return False

    def _validate_watch_directories(self) -> bool:
        """Valida que existan directorios para monitorear"""
        valid_count = 0
        for directory in self.monitor_config["watch_directories"]:
            if os.path.exists(directory) and os.path.isdir(directory):
                valid_count += 1
        return valid_count > 0

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcula hash SHA-256 de un archivo"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""

    def _get_uptime_seconds(self) -> float:
        """Calcula tiempo de actividad en segundos"""
        if self.stats["monitoring_start_time"]:
            return (
                datetime.now() - self.stats["monitoring_start_time"]
            ).total_seconds()
        return 0.0
