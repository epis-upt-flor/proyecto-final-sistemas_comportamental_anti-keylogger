"""
Plugin Network Monitor - Sistema de Monitoreo de Red
===================================================

Implementación de Plugin para monitoreo avanzado del tráfico de red con
detección de patrones sospechosos, análisis de conexiones y clasificación de amenazas.

Características:
- Monitoreo en tiempo real de conexiones de red
- Detección de patrones sospechosos de tráfico
- Análisis de procesos y puertos
- Clasificación de IPs y reputación básica
- Integración completa con Event Bus y Registry

Design Patterns Implementados:
- Template Method: Para estructura de plugin base
- Observer: Mediante Event Bus para comunicación
- Strategy: Para diferentes estrategias de análisis
- Chain of Responsibility: Para procesamiento de conexiones

Autor: Unified Antivirus Architecture
Versión: 3.1.0
Fecha: 2024-12-20
"""

import logging
import threading
import time
import socket
import psutil
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Callable, Any
from collections import deque
import json

# Importar infraestructura del core
from core.base_plugin import BasePlugin, PluginInterface
from core.event_bus import Event

logger = logging.getLogger(__name__)


class NetworkConnectionAnalyzer:
    """Analizador especializado para conexiones de red"""

    def __init__(self, config: Dict):
        self.config = config

        # Configuración de puertos y patrones
        self.suspicious_ports = set(
            config.get(
                "suspicious_ports",
                [21, 22, 23, 25, 53, 80, 443, 993, 995, 1080, 3389, 5900, 8080],
            )
        )

        self.system_processes = set(
            config.get(
                "system_processes",
                ["system", "svchost.exe", "explorer.exe", "dwm.exe", "winlogon.exe"],
            )
        )

        self.browser_processes = set(
            config.get(
                "browser_processes",
                ["chrome.exe", "firefox.exe", "msedge.exe", "safari.exe", "opera.exe"],
            )
        )

        self.suspicious_process_patterns = config.get(
            "suspicious_process_patterns",
            ["keylog", "capture", "monitor", "spy", "hack", "stealer", "backdoor"],
        )

        # Redes locales conocidas
        self.local_networks = [
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

        logger.info("[ANALYZER] Network Connection Analyzer inicializado")

    def analyze_connection(self, conn) -> Dict[str, Any]:
        """Análisis completo de una conexión de red"""
        try:
            return self._extract_connection_info(conn)
        except Exception as e:
            logger.error(f"[ERROR] Error analizando conexión: {e}")
            return {}

    def _extract_connection_info(self, conn) -> Dict[str, Any]:
        """Extrae información completa de una conexión"""
        try:
            # Información básica de la conexión
            conn_info = {
                "timestamp": datetime.now().isoformat(),
                "pid": conn.pid,
                "family": conn.family.name if conn.family else "unknown",
                "type": conn.type.name if conn.type else "unknown",
                "status": conn.status,
            }

            # Información de direcciones local y remota
            if conn.laddr:
                conn_info.update(
                    {
                        "local_ip": conn.laddr.ip,
                        "local_port": conn.laddr.port,
                        "src_ip": conn.laddr.ip,
                        "src_port": conn.laddr.port,
                    }
                )

            if conn.raddr:
                conn_info.update(
                    {
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "dst_ip": conn.raddr.ip,
                        "dst_port": conn.raddr.port,
                    }
                )

            # Información del proceso asociado
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    conn_info.update(
                        {
                            "process_name": process.name(),
                            "process_exe": process.exe(),
                            "process_cmdline": " ".join(
                                process.cmdline()[:3]
                            ),  # Solo primeros 3 args
                            "process_create_time": process.create_time(),
                            "process_memory_info": process.memory_info()._asdict(),
                            "process_cpu_percent": process.cpu_percent(),
                        }
                    )
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    conn_info.update(
                        {
                            "process_name": "unknown",
                            "process_exe": "unknown",
                            "process_cmdline": "unknown",
                            "process_create_time": 0,
                            "process_memory_info": {},
                            "process_cpu_percent": 0.0,
                        }
                    )

            # Calcular características adicionales y score de riesgo
            conn_info.update(self._calculate_connection_features(conn_info))

            return conn_info

        except Exception as e:
            logger.debug(f"Error extrayendo info de conexión: {e}")
            return {}

    def _calculate_connection_features(self, conn_info: Dict) -> Dict[str, Any]:
        """Calcula características avanzadas para la conexión"""
        features = {"risk_score": 0.0, "threat_indicators": []}

        try:
            # Análisis de puertos
            local_port = conn_info.get("local_port", 0)
            remote_port = conn_info.get("remote_port", 0)

            features.update(
                {
                    "is_suspicious_local_port": local_port in self.suspicious_ports,
                    "is_suspicious_remote_port": remote_port in self.suspicious_ports,
                    "is_high_port": remote_port > 1024,
                    "port_difference": (
                        abs(local_port - remote_port)
                        if local_port and remote_port
                        else 0
                    ),
                }
            )

            # Scoring por puertos
            if features["is_suspicious_remote_port"]:
                features["risk_score"] += 0.3
                features["threat_indicators"].append("suspicious_remote_port")

            # Análisis de direcciones IP
            remote_ip = conn_info.get("remote_ip", "")
            if remote_ip:
                ip_features = self._analyze_ip_address(remote_ip)
                features.update(ip_features)

                # Scoring por IP
                if not ip_features.get("is_local_network", False):
                    features["risk_score"] += 0.2
                    if ip_features.get("ip_reputation_risk", 0) > 0.5:
                        features["risk_score"] += 0.3
                        features["threat_indicators"].append("high_risk_ip")

            # Análisis del proceso
            process_name = conn_info.get("process_name", "").lower()
            process_features = self._analyze_process(process_name, conn_info)
            features.update(process_features)

            # Scoring por proceso
            if process_features.get("is_suspicious_process_name", False):
                features["risk_score"] += 0.5
                features["threat_indicators"].append("suspicious_process")

            if process_features.get("is_unknown_process", False):
                features["risk_score"] += 0.2
                features["threat_indicators"].append("unknown_process")

            # Análisis de comportamiento
            behavior_features = self._analyze_behavior_patterns(conn_info, features)
            features.update(behavior_features)

            # Normalizar score de riesgo
            features["risk_score"] = min(features["risk_score"], 1.0)

            # Clasificar severidad
            features["severity"] = self._calculate_severity(features["risk_score"])

        except Exception as e:
            logger.debug(f"Error calculando características: {e}")

        return features

    def _analyze_ip_address(self, ip: str) -> Dict[str, Any]:
        """Análisis específico de direcciones IP"""
        ip_features = {
            "is_local_network": False,
            "is_private_ip": False,
            "is_loopback": False,
            "ip_reputation_risk": 0.5,  # Riesgo medio por defecto
        }

        try:
            ip_obj = ipaddress.ip_address(ip)

            ip_features.update(
                {
                    "is_private_ip": ip_obj.is_private,
                    "is_loopback": ip_obj.is_loopback,
                    "is_local_network": any(
                        ip_obj in network for network in self.local_networks
                    ),
                }
            )

            # Calcular riesgo de reputación
            if ip_features["is_private_ip"] or ip_features["is_loopback"]:
                ip_features["ip_reputation_risk"] = 0.1  # Muy bajo riesgo
            elif ip_features["is_local_network"]:
                ip_features["ip_reputation_risk"] = 0.2  # Bajo riesgo
            else:
                # IP pública - riesgo medio a alto dependiendo de otros factores
                ip_features["ip_reputation_risk"] = 0.6

        except Exception as e:
            logger.debug(f"Error analizando IP {ip}: {e}")

        return ip_features

    def _analyze_process(self, process_name: str, conn_info: Dict) -> Dict[str, Any]:
        """Análisis específico del proceso"""
        process_features = {
            "is_system_process": False,
            "is_browser_process": False,
            "is_suspicious_process_name": False,
            "is_unknown_process": False,
        }

        try:
            process_name_lower = process_name.lower()

            process_features.update(
                {
                    "is_system_process": process_name_lower in self.system_processes,
                    "is_browser_process": process_name_lower in self.browser_processes,
                    "is_unknown_process": process_name == "unknown" or not process_name,
                    "is_suspicious_process_name": any(
                        pattern in process_name_lower
                        for pattern in self.suspicious_process_patterns
                    ),
                }
            )

            # Análisis adicional basado en la línea de comandos
            cmdline = conn_info.get("process_cmdline", "").lower()
            if cmdline and any(
                pattern in cmdline for pattern in self.suspicious_process_patterns
            ):
                process_features["is_suspicious_process_name"] = True

        except Exception as e:
            logger.debug(f"Error analizando proceso {process_name}: {e}")

        return process_features

    def _analyze_behavior_patterns(
        self, conn_info: Dict, features: Dict
    ) -> Dict[str, Any]:
        """Análisis de patrones de comportamiento"""
        behavior_features = {
            "connection_direction": "unknown",
            "is_outbound_connection": False,
            "is_encrypted_likely": False,
            "connection_type_risk": "low",
        }

        try:
            # Determinar dirección de la conexión
            local_port = conn_info.get("local_port", 0)
            remote_port = conn_info.get("remote_port", 0)

            if local_port and remote_port:
                if local_port > 1024 and remote_port <= 1024:
                    behavior_features["connection_direction"] = "outbound"
                    behavior_features["is_outbound_connection"] = True
                elif local_port <= 1024 and remote_port > 1024:
                    behavior_features["connection_direction"] = "inbound"
                else:
                    behavior_features["connection_direction"] = "peer_to_peer"

            # Verificar si probablemente usa encriptación
            encrypted_ports = {443, 993, 995, 22, 990}
            if remote_port in encrypted_ports:
                behavior_features["is_encrypted_likely"] = True

            # Evaluar riesgo del tipo de conexión
            if (
                behavior_features["is_outbound_connection"]
                and not features.get("is_browser_process", False)
                and not features.get("is_local_network", False)
            ):
                behavior_features["connection_type_risk"] = "medium"

                if features.get("is_suspicious_process_name", False):
                    behavior_features["connection_type_risk"] = "high"

        except Exception as e:
            logger.debug(f"Error analizando patrones de comportamiento: {e}")

        return behavior_features

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

    def is_suspicious_connection(self, conn_info: Dict) -> bool:
        """Determina si una conexión es sospechosa basado en múltiples criterios"""
        if not conn_info:
            return False

        risk_score = conn_info.get("risk_score", 0.0)
        threat_indicators = conn_info.get("threat_indicators", [])

        # Criterios de sospecha múltiples
        suspicious_criteria = [
            risk_score >= 0.6,
            len(threat_indicators) >= 2,
            conn_info.get("is_suspicious_process_name", False),
            (
                conn_info.get("is_outbound_connection", False)
                and not conn_info.get("is_browser_process", False)
                and not conn_info.get("is_local_network", False)
            ),
        ]

        return any(suspicious_criteria)


class NetworkMonitorPlugin(BasePlugin, PluginInterface):
    """
    Plugin de Monitoreo de Red - Implementación Template Method

    Proporciona monitoreo en tiempo real del tráfico de red con:
    - Detección de conexiones sospechosas
    - Análisis de procesos y puertos
    - Clasificación de IPs y reputación
    - Integración con Event Bus
    """

    def __init__(self):
        BasePlugin.__init__(self, "network_monitor", str(Path(__file__).parent))
        PluginInterface.__init__(self)
        self.plugin_type = "monitor"
        self.name = "network_monitor"
        self.version = "3.1.0"
        self.description = (
            "Monitor avanzado de tráfico de red con detección inteligente"
        )

        # Componentes especializados
        self.analyzer = None

        # Estado del monitoreo
        self.is_monitoring = False
        self.monitor_thread = None

        # Buffer de eventos y datos
        self.network_data = deque(maxlen=1000)
        self.suspicious_connections = set()

        # Estadísticas
        self.stats = {
            "connections_monitored": 0,
            "suspicious_connections_detected": 0,
            "packets_captured": 0,
            "events_processed": 0,
            "start_time": None,
            "last_activity": None,
        }

        logger.info("[PLUGIN] NetworkMonitorPlugin inicializado")

    # Template Method Pattern - Métodos base requeridos

    def initialize(self) -> bool:
        """Inicialización del plugin - Template Method Step 1"""
        try:
            logger.info(f"[INIT] Inicializando {self.name} v{self.version}")

            # Configuración por defecto
            self.config = self._get_default_config()

            # Inicializar componente analizador
            self.analyzer = NetworkConnectionAnalyzer(self.config)

            logger.info("[INIT] NetworkMonitorPlugin inicializado correctamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error inicializando NetworkMonitorPlugin: {e}")
            return False

    def configure(self, config: Dict) -> bool:
        """Configuración del plugin - Template Method Step 2"""
        try:
            logger.info("[CONFIG] Configurando NetworkMonitorPlugin")

            # Mergear con configuración por defecto
            self.config.update(config)

            # Reconfigurar analizador
            if self.analyzer:
                self.analyzer = NetworkConnectionAnalyzer(self.config)

            logger.info("[CONFIG] NetworkMonitorPlugin configurado exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error configurando NetworkMonitorPlugin: {e}")
            return False

    def start(self) -> bool:
        """Inicio del plugin - Template Method Step 3"""
        try:
            if self.is_monitoring:
                logger.warning("[WARNING] NetworkMonitorPlugin ya está ejecutándose")
                return True

            logger.info("[START] Iniciando NetworkMonitorPlugin")

            self.is_monitoring = True
            self.stats["start_time"] = datetime.now()

            # Iniciar hilo de monitoreo
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop, name="NetworkMonitorPlugin", daemon=True
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

            logger.info("[START] NetworkMonitorPlugin iniciado exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error iniciando NetworkMonitorPlugin: {e}")
            self.is_monitoring = False
            return False

    def stop(self) -> bool:
        """Detención del plugin - Template Method Step 4"""
        try:
            if not self.is_monitoring:
                logger.warning("[WARNING] NetworkMonitorPlugin no está ejecutándose")
                return True

            logger.info("[STOP] Deteniendo NetworkMonitorPlugin")

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

            logger.info("[STOP] NetworkMonitorPlugin detenido exitosamente")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error deteniendo NetworkMonitorPlugin: {e}")
            return False

    def cleanup(self) -> bool:
        """Limpieza del plugin - Template Method Step 5"""
        try:
            logger.info("[CLEANUP] Limpiando recursos de NetworkMonitorPlugin")

            # Asegurar que el monitoreo está detenido
            if self.is_monitoring:
                self.stop()

            # Limpiar buffers y estructuras
            self.network_data.clear()
            self.suspicious_connections.clear()

            # Resetear estadísticas
            self.stats = {
                "connections_monitored": 0,
                "suspicious_connections_detected": 0,
                "packets_captured": 0,
                "events_processed": 0,
                "start_time": None,
                "last_activity": None,
            }

            logger.info("[CLEANUP] Limpieza completada")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error en limpieza: {e}")
            return False

    # Métodos específicos del Plugin

    def _get_default_config(self) -> Dict:
        """Configuración por defecto del plugin"""
        return {
            "monitor_interval": 1.0,  # segundos
            "capture_outbound": True,
            "capture_inbound": True,
            "suspicious_ports": [
                21,
                22,
                23,
                25,
                53,
                80,
                443,
                993,
                995,
                1080,
                3389,
                5900,
                8080,
            ],
            "system_processes": [
                "system",
                "svchost.exe",
                "explorer.exe",
                "dwm.exe",
                "winlogon.exe",
            ],
            "browser_processes": [
                "chrome.exe",
                "firefox.exe",
                "msedge.exe",
                "safari.exe",
                "opera.exe",
            ],
            "suspicious_process_patterns": [
                "keylog",
                "capture",
                "monitor",
                "spy",
                "hack",
                "stealer",
                "backdoor",
            ],
            "max_connections_per_scan": 50,  # Limitar para rendimiento
            "enable_process_analysis": True,
            "enable_ip_reputation": True,
        }

    def _monitoring_loop(self):
        """Bucle principal de monitoreo de red"""
        logger.info("[MONITOR] Iniciando bucle de monitoreo de red...")

        while self.is_monitoring:
            try:
                self._capture_network_connections()
                time.sleep(self.config.get("monitor_interval", 1.0))

            except Exception as e:
                logger.error(f"[ERROR] Error en bucle de monitoreo: {e}")
                time.sleep(5)  # Pausa más larga en caso de error

    def _capture_network_connections(self):
        """Captura y procesa las conexiones de red activas"""
        try:
            # Obtener conexiones usando psutil
            connections = psutil.net_connections(kind="inet")

            connections_processed = 0
            max_connections = self.config.get("max_connections_per_scan", 50)

            for conn in connections:
                if connections_processed >= max_connections:
                    break

                try:
                    # Filtrar solo conexiones establecidas
                    if conn.status == psutil.CONN_ESTABLISHED:
                        conn_data = self.analyzer.analyze_connection(conn)
                        if conn_data:
                            self._process_connection(conn_data)
                            connections_processed += 1

                except Exception as e:
                    logger.debug(f"Error procesando conexión: {e}")
                    continue

            logger.debug(f"[ACTIVITY] Procesadas {connections_processed} conexiones")

        except Exception as e:
            logger.error(f"[ERROR] Error capturando conexiones: {e}")

    def _process_connection(self, conn_data: Dict):
        """Procesa una conexión individual"""
        try:
            # Añadir al buffer
            self.network_data.append(conn_data)
            self.stats["connections_monitored"] += 1
            self.stats["packets_captured"] += 1
            self.stats["last_activity"] = datetime.now()

            # Crear evento básico de conexión
            connection_event = {
                "type": "network_connection",
                "connection_data": conn_data,
                "timestamp": conn_data.get("timestamp", datetime.now().isoformat()),
                "plugin": self.name,
            }

            self.stats["events_processed"] += 1

            # Verificar si es sospechosa
            if self.analyzer.is_suspicious_connection(conn_data):
                self._flag_suspicious_connection(conn_data)

            # Publicar evento de conexión al Event Bus
            self._publish_event("network_connection", connection_event)

        except Exception as e:
            logger.error(f"[ERROR] Error procesando conexión: {e}")

    def _flag_suspicious_connection(self, conn_data: Dict):
        """Marca y procesa una conexión sospechosa"""
        connection_key = f"{conn_data.get('remote_ip', 'unknown')}:{conn_data.get('remote_port', 0)}:{conn_data.get('process_name', 'unknown')}"

        if connection_key not in self.suspicious_connections:
            self.suspicious_connections.add(connection_key)
            self.stats["suspicious_connections_detected"] += 1

            # Crear evento de amenaza
            threat_data = {
                "type": "suspicious_network_connection",
                "connection_data": conn_data,
                "remote_ip": conn_data.get("remote_ip", "unknown"),
                "remote_port": conn_data.get("remote_port", 0),
                "process_name": conn_data.get("process_name", "unknown"),
                "risk_score": conn_data.get("risk_score", 0.0),
                "threat_indicators": conn_data.get("threat_indicators", []),
                "severity": conn_data.get("severity", "medium"),
                "timestamp": conn_data.get("timestamp", datetime.now().isoformat()),
                "plugin": self.name,
            }

            logger.warning(
                f"[THREAT] Conexión sospechosa: {conn_data.get('remote_ip')}:{conn_data.get('remote_port')} desde {conn_data.get('process_name')} (score: {conn_data.get('risk_score', 0):.2f})"
            )

            # Publicar evento de amenaza al Event Bus
            self._publish_event("threat_detected", threat_data)

    def _publish_event(self, event_type: str, data: Dict):
        """Publica un evento al Event Bus"""
        try:
            if self.event_bus:
                event = Event(
                    type=event_type,
                    source=self.name,
                    data=data,
                    timestamp=datetime.now().isoformat(),
                )
                self.event_bus.publish(event)
        except Exception as e:
            logger.debug(f"Error publicando evento {event_type}: {e}")

    # Métodos de API pública

    def get_recent_data(self, count: Optional[int] = None) -> List[Dict]:
        """Obtiene datos recientes de conexiones"""
        if count is None:
            return list(self.network_data)
        else:
            return list(self.network_data)[-count:]

    def get_suspicious_connections(self) -> List[str]:
        """Obtiene lista de conexiones sospechosas activas"""
        return list(self.suspicious_connections)

    def get_stats(self) -> Dict:
        """Obtiene estadísticas completas del monitor"""
        stats = self.stats.copy()
        stats.update(
            {
                "suspicious_connections_active": len(self.suspicious_connections),
                "buffer_size": len(self.network_data),
                "is_monitoring": self.is_monitoring,
                "plugin_name": self.name,
                "plugin_version": self.version,
            }
        )

        if stats["start_time"]:
            uptime = (datetime.now() - stats["start_time"]).total_seconds()
            stats["uptime_seconds"] = uptime
            stats["uptime_formatted"] = str(datetime.now() - stats["start_time"]).split(
                "."
            )[0]
            stats["connections_per_second"] = stats["connections_monitored"] / max(
                uptime, 1
            )

        return stats

    def is_active(self) -> bool:
        """Verifica si el plugin está activo y monitoreando"""
        return (
            self.is_monitoring
            and self.monitor_thread
            and self.monitor_thread.is_alive()
        )

    def clear_data(self):
        """Limpia el buffer de datos"""
        self.network_data.clear()
        self.suspicious_connections.clear()
        logger.info("[CLEAN] Buffer de datos de red limpiado")

    def set_config(self, config: Dict):
        """Actualiza la configuración del monitor"""
        self.config.update(config)
        if self.analyzer:
            self.analyzer = NetworkConnectionAnalyzer(self.config)
        logger.info(f"[CONFIG] Configuración actualizada: {list(config.keys())}")

    def export_data(self, filepath: str, format_type: str = "json"):
        """Exporta datos capturados a un archivo"""
        try:
            data = list(self.network_data)

            if format_type.lower() == "json":
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2, default=str)

            elif format_type.lower() == "csv":
                try:
                    import pandas as pd

                    df = pd.DataFrame(data)
                    df.to_csv(filepath, index=False)
                except ImportError:
                    logger.error("[ERROR] pandas no disponible para exportar CSV")
                    return False

            logger.info(
                f"[EXPORT] Datos exportados a {filepath} ({len(data)} registros)"
            )
            return True

        except Exception as e:
            logger.error(f"[ERROR] Error exportando datos: {e}")
            return False

    def force_scan(self):
        """Fuerza un escaneo inmediato de conexiones"""
        if self.is_monitoring:
            logger.info("[FORCE-SCAN] Ejecutando escaneo forzado de red...")
            self._capture_network_connections()
            logger.info("[FORCE-SCAN] Escaneo forzado completado")

    def get_connection_summary(self) -> Dict:
        """Obtiene resumen de conexiones por categorías"""
        summary = {
            "total_connections": len(self.network_data),
            "suspicious_connections": len(self.suspicious_connections),
            "by_process": {},
            "by_remote_port": {},
            "by_severity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        }

        try:
            for conn in self.network_data:
                # Por proceso
                process_name = conn.get("process_name", "unknown")
                summary["by_process"][process_name] = (
                    summary["by_process"].get(process_name, 0) + 1
                )

                # Por puerto remoto
                remote_port = conn.get("remote_port", 0)
                summary["by_remote_port"][str(remote_port)] = (
                    summary["by_remote_port"].get(str(remote_port), 0) + 1
                )

                # Por severidad
                severity = conn.get("severity", "info")
                if severity in summary["by_severity"]:
                    summary["by_severity"][severity] += 1

        except Exception as e:
            logger.error(f"[ERROR] Error generando resumen: {e}")

        return summary

    def get_plugin_info(self) -> Dict:
        """Información completa del plugin"""
        return {
            "name": self.name,
            "type": self.plugin_type,
            "version": self.version,
            "description": self.description,
            "is_active": self.is_active(),
            "capabilities": [
                "network_monitoring",
                "connection_analysis",
                "threat_detection",
                "process_correlation",
                "ip_reputation_check",
                "port_classification",
                "behavior_analysis",
                "real_time_scanning",
            ],
            "config": {
                "monitor_interval": self.config.get("monitor_interval", 1.0),
                "max_connections_per_scan": self.config.get(
                    "max_connections_per_scan", 50
                ),
                "suspicious_ports_count": len(self.config.get("suspicious_ports", [])),
                "process_analysis_enabled": self.config.get(
                    "enable_process_analysis", True
                ),
                "ip_reputation_enabled": self.config.get("enable_ip_reputation", True),
            },
        }

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
                if "network_monitor" in new_config:
                    self.configure(new_config["network_monitor"])

            elif event_type == "ip_reputation_update":
                logger.info("[EVENT] Recibida actualización de reputación IP")
                malicious_ips = data.get("malicious_ips", [])
                if malicious_ips and hasattr(self.analyzer, "update_malicious_ips"):
                    self.analyzer.update_malicious_ips(malicious_ips)

            elif event_type == "force_network_scan":
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
        """Información específica del NetworkMonitorPlugin"""
        return {
            "name": self.name,
            "version": self.version,
            "type": self.plugin_type,
            "description": self.description,
            "status": "active" if self.is_monitoring else "inactive",
            "capabilities": [
                "network_traffic_monitoring",
                "connection_analysis",
                "ip_reputation_checking",
                "suspicious_port_detection",
                "process_network_correlation",
                "connection_blocking",
                "real_time_network_analysis",
                "threat_pattern_detection",
            ],
            "stats": self.get_stats(),
            "config_summary": {
                "scan_interval": self.config.get("scan_interval", 5.0),
                "max_connections_per_scan": self.config.get(
                    "max_connections_per_scan", 50
                ),
                "suspicious_ports_count": len(self.config.get("suspicious_ports", [])),
                "process_analysis_enabled": self.config.get(
                    "enable_process_analysis", True
                ),
                "ip_reputation_enabled": self.config.get("enable_ip_reputation", True),
            },
        }


def test_network_monitor_plugin():
    """Función de test integrado para el Network Monitor Plugin"""
    import sys
    import os

    # Agregar el directorio core al path para importar las interfaces
    sys.path.insert(
        0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "core")
    )

    def mock_event_callback(event):
        print(f"📢 Evento recibido: {event.type} desde {event.source}")
        if event.type == "threat_detected":
            data = event.data
            print(
                f"   🚨 AMENAZA: {data.get('remote_ip', 'N/A')}:{data.get('remote_port', 'N/A')}"
            )
            print(f"   📊 Risk Score: {data.get('risk_score', 0):.2f}")
            print(f"   🔧 Proceso: {data.get('process_name', 'N/A')}")
            print(f"   ⚡ Severidad: {data.get('severity', 'N/A')}")
        elif event.type == "network_connection":
            # Solo mostrar algunas conexiones para no saturar
            pass

    print("🧪 ===== TEST NETWORK MONITOR PLUGIN =====")

    try:
        # Crear plugin
        plugin = NetworkMonitorPlugin()

        # Configuración de test
        test_config = {
            "monitor_interval": 1.5,  # Más lento para test
            "max_connections_per_scan": 20,  # Limitar para test
            "enable_process_analysis": True,
            "enable_ip_reputation": True,
        }

        # Simular event bus simple
        class MockEventBus:
            def __init__(self, callback):
                self.callback = callback

            def publish(self, event):
                if self.callback:
                    self.callback(event)

        plugin.event_bus = MockEventBus(mock_event_callback)

        # Test del ciclo de vida completo
        print("\n1️⃣ Inicializando plugin...")
        assert plugin.initialize(), "❌ Error en initialize()"
        print("✅ Plugin inicializado")

        print("\n2️⃣ Configurando plugin...")
        assert plugin.configure(test_config), "❌ Error en configure()"
        print("✅ Plugin configurado")

        print("\n3️⃣ Iniciando plugin...")
        assert plugin.start(), "❌ Error en start()"
        print("✅ Plugin iniciado")

        print("\n4️⃣ Verificando estado...")
        assert plugin.is_active(), "❌ Plugin no está activo"
        print("✅ Plugin activo y monitoreando")

        print("\n5️⃣ Ejecutando monitoreo por 20 segundos...")
        for i in range(10):  # 10 ciclos de ~2 segundos
            time.sleep(2)
            stats = plugin.get_stats()
            print(
                f"   [{i*2+2:2d}s] Conexiones: {stats['connections_monitored']}, Sospechosas: {stats['suspicious_connections_active']}, Rate: {stats.get('connections_per_second', 0):.1f}/s"
            )

            # Mostrar conexiones sospechosas si hay
            suspicious = plugin.get_suspicious_connections()
            if suspicious:
                print(f"        🚨 {len(suspicious)} conexiones sospechosas:")
                for suspicious_conn in suspicious[:3]:  # Solo las primeras 3
                    print(f"          - {suspicious_conn}")

        print("\n6️⃣ Resumen de conexiones:")
        summary = plugin.get_connection_summary()
        print(f"   📊 Total: {summary['total_connections']}")
        print(f"   🚨 Sospechosas: {summary['suspicious_connections']}")
        print(f"   🔧 Procesos únicos: {len(summary['by_process'])}")
        print(f"   🔌 Puertos únicos: {len(summary['by_remote_port'])}")

        # Mostrar top procesos
        if summary["by_process"]:
            top_processes = sorted(
                summary["by_process"].items(), key=lambda x: x[1], reverse=True
            )[:3]
            print(
                f"   📋 Top procesos: {', '.join([f'{p}({c})' for p, c in top_processes])}"
            )

        print("\n7️⃣ Información del plugin:")
        info = plugin.get_plugin_info()
        print(f"   📋 Nombre: {info['name']} v{info['version']}")
        print(f"   🔧 Capacidades: {len(info['capabilities'])}")
        print(
            f"   ⚙️ Conexiones por escaneo: {info['config']['max_connections_per_scan']}"
        )

        print("\n8️⃣ Estadísticas finales:")
        final_stats = plugin.get_stats()
        for key, value in final_stats.items():
            if key not in ["start_time"]:
                print(f"   {key}: {value}")

        print("\n9️⃣ Deteniendo plugin...")
        assert plugin.stop(), "❌ Error en stop()"
        print("✅ Plugin detenido")

        print("\n🔟 Limpiando recursos...")
        assert plugin.cleanup(), "❌ Error en cleanup()"
        print("✅ Recursos limpiados")

        print("\n🎉 ¡Test exitoso! Network Monitor Plugin funciona correctamente")

        return True

    except Exception as e:
        print(f"\n❌ Error durante el test: {e}")
        import traceback

        traceback.print_exc()
        return False

    except KeyboardInterrupt:
        print("\n⏹️ Test interrumpido por usuario")
        if "plugin" in locals():
            plugin.stop()
            plugin.cleanup()
        return False


if __name__ == "__main__":
    # Ejecutar test si se ejecuta directamente
    test_network_monitor_plugin()
