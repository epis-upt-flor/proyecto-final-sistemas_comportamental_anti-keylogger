"""
Monitor de Red - Plugin para vigilancia de conexiones de red
==========================================================

Monitorea conexiones de red en tiempo real para detectar comunicaciones
sospechosas, conexiones no autorizadas y actividad de keyloggers remotos.
"""

import psutil
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
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


class NetworkMonitorPlugin(BasePlugin, MonitorPluginInterface):
    """Monitor de red con detección de actividad sospechosa"""

    def __init__(self, name: str, version: str):
        super().__init__(name, version)

        # Estado del monitor
        self.is_monitoring = False
        self.monitor_thread = None

        # Configuración de monitoreo
        self.monitor_config = {
            "update_interval": 3.0,  # segundos
            "track_new_connections": True,
            "track_data_volumes": True,
            "suspicious_ports": [
                1080,
                1081,
                4444,
                4445,
                5555,
                6666,
                7777,
                8080,
                9999,
                31337,
                12345,
                54321,
                65535,
            ],
            "suspicious_domains": [
                "tempmail",
                "guerrilla",
                "mailinator",
                "10minute",
                "pastebin",
                "hastebin",
                "ghostbin",
            ],
            "high_traffic_threshold_mb": 100,  # MB por minuto
            "max_connections_per_process": 50,
            "whitelist_processes": ["chrome.exe", "firefox.exe", "msedge.exe"],
            "alert_external_connections": True,
        }

        # Estado de conexiones
        self.known_connections = set()
        self.connection_history = []
        self.process_connections = {}

        # Estadísticas de tráfico
        self.traffic_stats = {}

        # Estadísticas generales
        self.stats = {
            "total_connections_monitored": 0,
            "suspicious_connections_detected": 0,
            "new_connections_detected": 0,
            "high_traffic_alerts": 0,
            "monitoring_start_time": None,
        }

        # IPs y dominios sospechosos conocidos
        self.suspicious_ips = set()
        self.suspicious_domains = set()

    def initialize(self) -> bool:
        """Inicializa el monitor de red"""
        try:
            self.setup_logging()
            self.load_config()

            if hasattr(self, "logger"):
                self.logger.info("Inicializando NetworkMonitor...")

            # Cargar configuración específica
            network_config = self.config.get("network_monitor", {})
            self.monitor_config.update(network_config)

            # Verificar psutil para conexiones de red
            if not self._check_network_capabilities():
                if hasattr(self, "logger"):
                    self.logger.error("❌ Capacidades de red no disponibles")
                return False

            # Obtener snapshot inicial de conexiones
            self._initialize_network_snapshot()

            # Cargar listas de IPs/dominios sospechosos
            self._load_threat_intelligence()

            if hasattr(self, "logger"):
                self.logger.info("✅ NetworkMonitor inicializado correctamente")
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error inicializando NetworkMonitor: {e}")
            return False

    def start(self) -> bool:
        """Inicia el monitoreo de red"""
        try:
            if self.is_monitoring:
                if hasattr(self, "logger"):
                    self.logger.warning("⚠️ NetworkMonitor ya está activo")
                return True

            if hasattr(self, "logger"):
                self.logger.info("🚀 Iniciando monitoreo de red...")

            # Iniciar thread de monitoreo
            self.monitor_thread = threading.Thread(
                target=self._monitor_network_loop, daemon=True
            )

            self.is_monitoring = True
            self.stats["monitoring_start_time"] = datetime.now()

            self.monitor_thread.start()

            # Notificar inicio
            if hasattr(self, "event_publisher") and self.event_publisher:
                self.publish_event(
                    "monitor_started",
                    {
                        "monitor_type": "network",
                        "timestamp": datetime.now().isoformat(),
                    },
                )

            if hasattr(self, "logger"):
                self.logger.info("✅ NetworkMonitor iniciado exitosamente")
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error iniciando NetworkMonitor: {e}")
            self.is_monitoring = False
            return False

    def stop(self) -> bool:
        """Detiene el monitoreo de red"""
        try:
            if not self.is_monitoring:
                if hasattr(self, "logger"):
                    self.logger.warning("⚠️ NetworkMonitor no está activo")
                return True

            if hasattr(self, "logger"):
                self.logger.info("🛑 Deteniendo monitoreo de red...")

            self.is_monitoring = False

            # Esperar que termine el thread
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5.0)

            # Notificar parada
            if hasattr(self, "event_publisher") and self.event_publisher:
                self.publish_event(
                    "monitor_stopped",
                    {
                        "monitor_type": "network",
                        "timestamp": datetime.now().isoformat(),
                        "stats": self.stats.copy(),
                    },
                )

            if hasattr(self, "logger"):
                self.logger.info("✅ NetworkMonitor detenido")
            return True

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error deteniendo NetworkMonitor: {e}")
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
            "monitor_type": "network",
            "target": "network_connections",
            "uptime_seconds": self._get_uptime_seconds(),
            "stats": self.stats.copy(),
            "config": self.monitor_config.copy(),
        }

    def get_monitoring_results(self) -> List[Dict[str, Any]]:
        """Obtiene resultados del monitoreo"""
        return self.connection_history.copy()

    # ================= CORE MONITORING LOGIC =================
    def _monitor_network_loop(self):
        """Loop principal de monitoreo de red"""

        if hasattr(self, "logger"):
            self.logger.info("📊 Iniciando loop de monitoreo de red")

        while self.is_monitoring:
            try:
                # Obtener conexiones actuales
                current_connections = self._get_current_connections()

                # Detectar nuevas conexiones
                if self.monitor_config["track_new_connections"]:
                    self._check_new_connections(current_connections)

                # Verificar conexiones sospechosas
                self._check_suspicious_connections(current_connections)

                # Monitorear volúmenes de datos
                if self.monitor_config["track_data_volumes"]:
                    self._check_traffic_volumes()

                # Verificar procesos con muchas conexiones
                self._check_process_connection_counts(current_connections)

                # Actualizar estadísticas
                self.stats["total_connections_monitored"] = len(current_connections)

                # Esperar próximo ciclo
                time.sleep(self.monitor_config["update_interval"])

            except Exception as e:
                if hasattr(self, "logger"):
                    self.logger.error(f"❌ Error en loop de monitoreo de red: {e}")
                time.sleep(1.0)  # Esperar antes de reintentar

        if hasattr(self, "logger"):
            self.logger.info("🏁 Loop de monitoreo de red terminado")

    def _get_current_connections(self) -> List[Dict[str, Any]]:
        """Obtiene lista de conexiones de red actuales"""

        connections = []

        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    # Información básica de conexión
                    conn_info = {
                        "fd": conn.fd,
                        "family": conn.family.name if conn.family else "unknown",
                        "type": conn.type.name if conn.type else "unknown",
                        "local_addr": (
                            f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                        ),
                        "remote_addr": (
                            f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                        ),
                        "status": conn.status,
                        "pid": conn.pid,
                    }

                    # Obtener información del proceso si existe
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            conn_info["process_name"] = process.name()
                            conn_info["process_exe"] = process.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            conn_info["process_name"] = "unknown"
                            conn_info["process_exe"] = "unknown"

                    connections.append(conn_info)

                except Exception:
                    # Error con conexión específica, continuar
                    continue

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error obteniendo conexiones: {e}")

        return connections

    def _check_new_connections(self, current_connections: List[Dict[str, Any]]):
        """Detecta nuevas conexiones de red"""

        current_conn_ids = set()

        for conn in current_connections:
            # Crear ID único para la conexión
            conn_id = (
                f"{conn.get('pid')}_{conn.get('local_addr')}_{conn.get('remote_addr')}"
            )
            current_conn_ids.add(conn_id)

            if conn_id not in self.known_connections:
                self.stats["new_connections_detected"] += 1

                # Crear evento de nueva conexión
                event_data = {
                    "event_type": "new_network_connection",
                    "connection_id": conn_id,
                    "pid": conn.get("pid"),
                    "process_name": conn.get("process_name"),
                    "local_addr": conn.get("local_addr"),
                    "remote_addr": conn.get("remote_addr"),
                    "status": conn.get("status"),
                    "timestamp": datetime.now().isoformat(),
                    "suspicious_score": self._calculate_connection_suspicion_score(
                        conn
                    ),
                }

                # Agregar a historial
                self.connection_history.append(event_data)

                # Publicar evento
                if hasattr(self, "event_publisher") and self.event_publisher:
                    self.publish_event("new_network_connection", event_data)

                if hasattr(self, "logger"):
                    self.logger.info(
                        f"🔗 Nueva conexión: {conn.get('process_name')} -> {conn.get('remote_addr')}"
                    )

        # Actualizar conjunto de conexiones conocidas
        self.known_connections.update(current_conn_ids)

    def _check_suspicious_connections(self, current_connections: List[Dict[str, Any]]):
        """Verifica conexiones sospechosas"""

        for conn in current_connections:
            if self._is_connection_suspicious(conn):
                self._alert_suspicious_connection(conn)

    def _check_traffic_volumes(self):
        """Monitorea volúmenes de tráfico de red"""

        try:
            net_io = psutil.net_io_counters()
            current_time = datetime.now()

            # Calcular diferencia desde última medición
            if hasattr(self, "_last_net_io"):
                time_diff = (current_time - self._last_time).total_seconds()

                if time_diff > 0:
                    bytes_sent_diff = net_io.bytes_sent - self._last_net_io.bytes_sent
                    bytes_recv_diff = net_io.bytes_recv - self._last_net_io.bytes_recv

                    # Convertir a MB por minuto
                    mb_sent_per_min = (bytes_sent_diff / (1024 * 1024)) * (
                        60 / time_diff
                    )
                    mb_recv_per_min = (bytes_recv_diff / (1024 * 1024)) * (
                        60 / time_diff
                    )

                    # Verificar umbral de tráfico alto
                    threshold = self.monitor_config["high_traffic_threshold_mb"]

                    if mb_sent_per_min > threshold or mb_recv_per_min > threshold:
                        self._alert_high_traffic(mb_sent_per_min, mb_recv_per_min)

            # Guardar medición actual
            self._last_net_io = net_io
            self._last_time = current_time

        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error verificando tráfico: {e}")

    def _check_process_connection_counts(
        self, current_connections: List[Dict[str, Any]]
    ):
        """Verifica procesos con demasiadas conexiones"""

        process_conn_counts = {}

        for conn in current_connections:
            pid = conn.get("pid")
            if pid:
                process_conn_counts[pid] = process_conn_counts.get(pid, 0) + 1

        # Verificar procesos con muchas conexiones
        for pid, count in process_conn_counts.items():
            if count > self.monitor_config["max_connections_per_process"]:
                self._alert_high_connection_count(pid, count)

    def _is_connection_suspicious(self, conn: Dict[str, Any]) -> bool:
        """Determina si una conexión es sospechosa"""

        remote_addr = conn.get("remote_addr", "")
        process_name = conn.get("process_name", "").lower()

        # Verificar proceso en whitelist
        if any(
            whitelist_proc.lower() in process_name
            for whitelist_proc in self.monitor_config["whitelist_processes"]
        ):
            return False

        # Verificar puerto sospechoso
        if remote_addr:
            try:
                port = int(remote_addr.split(":")[-1])
                if port in self.monitor_config["suspicious_ports"]:
                    return True
            except ValueError:
                pass

        # Verificar IP sospechosa
        if remote_addr and any(ip in remote_addr for ip in self.suspicious_ips):
            return True

        # Verificar conexiones externas si está habilitado
        if self.monitor_config["alert_external_connections"] and remote_addr:
            try:
                ip = remote_addr.split(":")[0]
                if not self._is_local_ip(ip):
                    return True
            except Exception:
                pass

        return False

    def _calculate_connection_suspicion_score(self, conn: Dict[str, Any]) -> float:
        """Calcula puntuación de sospecha para una conexión"""

        score = 0.0

        remote_addr = conn.get("remote_addr", "")
        process_name = conn.get("process_name", "").lower()

        # Puntuación por puerto sospechoso
        if remote_addr:
            try:
                port = int(remote_addr.split(":")[-1])
                if port in self.monitor_config["suspicious_ports"]:
                    score += 0.4
            except ValueError:
                pass

        # Puntuación por nombre de proceso sospechoso
        suspicious_names = ["keylog", "spy", "trojan", "backdoor", "stealer"]
        for suspicious_name in suspicious_names:
            if suspicious_name in process_name:
                score += 0.5
                break

        # Puntuación por conexión externa
        if remote_addr and not self._is_local_ip(remote_addr.split(":")[0]):
            score += 0.2

        return min(score, 1.0)

    def _alert_suspicious_connection(self, conn: Dict[str, Any]):
        """Genera alerta por conexión sospechosa"""

        self.stats["suspicious_connections_detected"] += 1

        event_data = {
            "event_type": "suspicious_network_connection",
            "pid": conn.get("pid"),
            "process_name": conn.get("process_name"),
            "local_addr": conn.get("local_addr"),
            "remote_addr": conn.get("remote_addr"),
            "suspicious_score": self._calculate_connection_suspicion_score(conn),
            "timestamp": datetime.now().isoformat(),
        }

        self.connection_history.append(event_data)

        if hasattr(self, "event_publisher") and self.event_publisher:
            self.publish_event("suspicious_network_connection", event_data)

        if hasattr(self, "logger"):
            self.logger.warning(
                f"🚨 Conexión sospechosa: {conn.get('process_name')} -> {conn.get('remote_addr')}"
            )

    def _alert_high_traffic(self, mb_sent: float, mb_recv: float):
        """Genera alerta por tráfico alto"""

        self.stats["high_traffic_alerts"] += 1

        event_data = {
            "event_type": "high_network_traffic",
            "mb_sent_per_minute": mb_sent,
            "mb_recv_per_minute": mb_recv,
            "threshold_mb": self.monitor_config["high_traffic_threshold_mb"],
            "timestamp": datetime.now().isoformat(),
        }

        if hasattr(self, "event_publisher") and self.event_publisher:
            self.publish_event("high_network_traffic", event_data)

        if hasattr(self, "logger"):
            self.logger.warning(
                f"📊 Tráfico alto detectado: {mb_sent:.1f}MB/min enviado, {mb_recv:.1f}MB/min recibido"
            )

    def _alert_high_connection_count(self, pid: int, count: int):
        """Genera alerta por proceso con muchas conexiones"""

        try:
            process = psutil.Process(pid)
            process_name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "unknown"

        event_data = {
            "event_type": "high_connection_count",
            "pid": pid,
            "process_name": process_name,
            "connection_count": count,
            "threshold": self.monitor_config["max_connections_per_process"],
            "timestamp": datetime.now().isoformat(),
        }

        if hasattr(self, "event_publisher") and self.event_publisher:
            self.publish_event("high_connection_count", event_data)

        if hasattr(self, "logger"):
            self.logger.warning(
                f"🔗 Muchas conexiones: {process_name} ({count} conexiones)"
            )

    # ================= UTILITY METHODS =================
    def _check_network_capabilities(self) -> bool:
        """Verifica capacidades de monitoreo de red"""
        try:
            psutil.net_connections()
            psutil.net_io_counters()
            return True
        except Exception:
            return False

    def _initialize_network_snapshot(self):
        """Inicializa snapshot de conexiones actuales"""
        try:
            current_connections = self._get_current_connections()
            for conn in current_connections:
                conn_id = f"{conn.get('pid')}_{conn.get('local_addr')}_{conn.get('remote_addr')}"
                self.known_connections.add(conn_id)

            if hasattr(self, "logger"):
                self.logger.info(
                    f"📊 Snapshot inicial: {len(self.known_connections)} conexiones"
                )
        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.error(f"❌ Error en snapshot de red: {e}")

    def _load_threat_intelligence(self):
        """Carga listas de IPs y dominios sospechosos"""
        # En implementación real, esto cargaría de feeds de threat intelligence
        self.suspicious_ips.update(["192.168.100.100", "10.0.0.100"])  # IPs de ejemplo

    def _is_local_ip(self, ip: str) -> bool:
        """Verifica si una IP es local"""
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except Exception:
            return False

    def _get_uptime_seconds(self) -> float:
        """Calcula tiempo de actividad en segundos"""
        if self.stats["monitoring_start_time"]:
            return (
                datetime.now() - self.stats["monitoring_start_time"]
            ).total_seconds()
        return 0.0
