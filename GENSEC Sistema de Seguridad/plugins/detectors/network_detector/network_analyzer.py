"""
📊 Network Analyzer - Análisis de Tráfico de Red
================================================

Componente especializado en el análisis detallado de conexiones de red.

Implementa:
- Strategy Pattern: Diferentes estrategias de análisis según protocolo
- Template Method: Proceso estándar de análisis de conexiones
- Observer Pattern: Monitoreo continuo de tráfico de red
"""

import os
import sys
import json
import time
import psutil
import logging
import threading
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path


@dataclass
class NetworkStats:
    """Estadísticas de red por conexión."""

    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    first_seen: datetime
    last_seen: datetime
    connection_count: int

    @property
    def upload_ratio(self) -> float:
        """Calcula ratio de upload vs download."""
        total = self.bytes_sent + self.bytes_received
        return self.bytes_sent / max(total, 1)

    @property
    def duration_seconds(self) -> float:
        """Duración de la conexión en segundos."""
        return (self.last_seen - self.first_seen).total_seconds()


class NetworkAnalyzer:
    """
    📊 Analizador de tráfico de red para detección de patrones maliciosos.

    Implementa Template Method para análisis estándar:
    1. Captura de conexiones activas
    2. Análisis de estadísticas de tráfico
    3. Detección de patrones anómalos
    4. Correlación temporal de conexiones
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("network_analyzer")

        # Configuración de análisis
        self.analysis_config = config.get("network_config", {})
        self.analysis_window = self.analysis_config.get("analysis_window_minutes", 10)
        self.max_connections = self.analysis_config.get(
            "max_connections_per_minute", 50
        )

        # Estado interno
        self.connection_stats: Dict[str, NetworkStats] = {}
        self.process_connections: Dict[int, List[str]] = defaultdict(list)
        self.timeline: deque = deque(maxlen=10000)
        self.analysis_lock = threading.Lock()

        # Métricas
        self.metrics = {
            "total_connections": 0,
            "active_connections": 0,
            "suspicious_patterns": 0,
            "analysis_cycles": 0,
        }

    async def initialize(self) -> bool:
        """Inicializa el analizador de red."""
        try:
            self.logger.info("📊 Inicializando Network Analyzer...")

            # Verificar capacidades del sistema
            if not self._check_system_capabilities():
                return False

            # Configurar baseline de red
            await self._establish_network_baseline()

            self.logger.info("✅ Network Analyzer inicializado")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error inicializando Network Analyzer: {e}")
            return False

    def _check_system_capabilities(self) -> bool:
        """Verifica capacidades del sistema para análisis de red."""
        try:
            # Verificar acceso a conexiones de red
            connections = psutil.net_connections(kind="inet")
            self.logger.info(
                f"🔍 Sistema soporta análisis de red: {len(connections)} conexiones detectadas"
            )
            return True
        except Exception as e:
            self.logger.error(f"❌ Sistema no soporta análisis de red: {e}")
            return False

    async def _establish_network_baseline(self):
        """Establece baseline de comportamiento normal de red."""
        try:
            self.logger.info("📏 Estableciendo baseline de red...")

            # Capturar estado inicial
            initial_connections = self.get_active_connections()

            # Estadísticas baseline
            self.baseline = {
                "normal_connection_count": len(initial_connections),
                "established_time": datetime.now(),
                "common_ports": self._analyze_common_ports(initial_connections),
                "process_patterns": self._analyze_process_patterns(initial_connections),
            }

            self.logger.info(
                f"📏 Baseline establecido: {len(initial_connections)} conexiones normales"
            )

        except Exception as e:
            self.logger.error(f"❌ Error estableciendo baseline: {e}")

    # ==================== TEMPLATE METHOD ====================

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """
        🎯 Template Method: Obtiene y procesa conexiones activas.

        Steps:
        1. Capturar conexiones del sistema
        2. Filtrar conexiones relevantes
        3. Enriquecer con datos de proceso
        4. Aplicar análisis de patrones
        """
        try:
            # Step 1: Capturar conexiones
            raw_connections = self._capture_system_connections()

            # Step 2: Filtrar relevantes
            filtered_connections = self._filter_relevant_connections(raw_connections)

            # Step 3: Enriquecer con procesos
            enriched_connections = self._enrich_with_process_data(filtered_connections)

            # Step 4: Análisis de patrones
            analyzed_connections = self._analyze_connection_patterns(
                enriched_connections
            )

            self.metrics["analysis_cycles"] += 1
            return analyzed_connections

        except Exception as e:
            self.logger.error(f"❌ Error obteniendo conexiones activas: {e}")
            return []

    def _capture_system_connections(self) -> List[Dict[str, Any]]:
        """Step 1: Captura conexiones del sistema."""
        connections = []

        try:
            # Obtener conexiones de red
            net_connections = psutil.net_connections(kind="inet")

            for conn in net_connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    connection_data = {
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else "",
                        "remote_port": conn.raddr.port if conn.raddr else 0,
                        "protocol": "TCP" if conn.type == 1 else "UDP",
                        "status": conn.status,
                        "pid": conn.pid,
                        "timestamp": datetime.now(),
                    }
                    connections.append(connection_data)

            self.metrics["total_connections"] = len(connections)
            return connections

        except Exception as e:
            self.logger.error(f"❌ Error capturando conexiones: {e}")
            return []

    def _filter_relevant_connections(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Step 2: Filtra conexiones relevantes para análisis."""
        filtered = []

        for conn in connections:
            # Filtrar conexiones locales
            remote_ip = conn.get("remote_ip", "")
            if self._is_local_ip(remote_ip):
                continue

            # Filtrar puertos del sistema
            remote_port = conn.get("remote_port", 0)
            if self._is_system_port(remote_port):
                continue

            # Filtrar procesos del sistema
            if conn.get("pid") and self._is_system_process(conn.get("pid")):
                continue

            filtered.append(conn)

        self.metrics["active_connections"] = len(filtered)
        return filtered

    def _enrich_with_process_data(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Step 3: Enriquece conexiones con datos de proceso."""
        enriched = []

        for conn in connections:
            try:
                pid = conn.get("pid")
                if pid:
                    process = psutil.Process(pid)

                    # Agregar información del proceso
                    conn.update(
                        {
                            "process_name": process.name(),
                            "process_exe": (
                                process.exe() if hasattr(process, "exe") else ""
                            ),
                            "process_cmdline": (
                                " ".join(process.cmdline())
                                if hasattr(process, "cmdline")
                                else ""
                            ),
                            "process_create_time": datetime.fromtimestamp(
                                process.create_time()
                            ),
                            "process_cpu_percent": process.cpu_percent(),
                            "process_memory_mb": process.memory_info().rss
                            / 1024
                            / 1024,
                        }
                    )

                    # Agregar estadísticas de red del proceso
                    try:
                        net_io = process.net_io_counters()
                        if net_io:
                            conn.update(
                                {
                                    "bytes_sent": net_io.bytes_sent,
                                    "bytes_recv": net_io.bytes_recv,
                                    "packets_sent": net_io.packets_sent,
                                    "packets_recv": net_io.packets_recv,
                                }
                            )
                    except:
                        pass

                enriched.append(conn)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Proceso terminado o sin acceso
                continue
            except Exception as e:
                self.logger.warning(f"⚠️ Error enriqueciendo conexión: {e}")
                enriched.append(conn)

        return enriched

    def _analyze_connection_patterns(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Step 4: Analiza patrones en las conexiones."""
        analyzed = []

        with self.analysis_lock:
            for conn in connections:
                # Generar ID único de conexión
                conn_id = f"{conn.get('remote_ip')}:{conn.get('remote_port')}"

                # Actualizar estadísticas
                self._update_connection_stats(conn_id, conn)

                # Agregar análisis de patrones
                conn["pattern_analysis"] = self._analyze_single_connection(conn)

                # Agregar a timeline
                self.timeline.append(
                    {
                        "timestamp": conn.get("timestamp"),
                        "connection_id": conn_id,
                        "remote_ip": conn.get("remote_ip"),
                        "process_name": conn.get("process_name", ""),
                        "bytes_sent": conn.get("bytes_sent", 0),
                    }
                )

                analyzed.append(conn)

        return analyzed

    # ==================== STRATEGY PATTERN ====================

    def _analyze_single_connection(self, connection: Dict[str, Any]) -> Dict[str, Any]:
        """
        🎯 Strategy Pattern: Aplica diferentes estrategias de análisis según características.
        """
        analysis = {}

        # Estrategia por protocolo
        protocol = connection.get("protocol", "TCP")
        if protocol == "TCP":
            analysis.update(self._analyze_tcp_connection(connection))
        elif protocol == "UDP":
            analysis.update(self._analyze_udp_connection(connection))

        # Estrategia por puerto
        port = connection.get("remote_port", 0)
        analysis.update(self._analyze_by_port(connection, port))

        # Estrategia por proceso
        process_name = connection.get("process_name", "")
        analysis.update(self._analyze_by_process(connection, process_name))

        # Estrategia por tráfico
        bytes_sent = connection.get("bytes_sent", 0)
        bytes_recv = connection.get("bytes_recv", 0)
        analysis.update(self._analyze_traffic_pattern(bytes_sent, bytes_recv))

        return analysis

    def _analyze_tcp_connection(self, connection: Dict[str, Any]) -> Dict[str, Any]:
        """Estrategia de análisis para conexiones TCP."""
        analysis = {"protocol_analysis": "tcp"}

        remote_port = connection.get("remote_port", 0)

        # Análisis por categoría de puerto
        if remote_port in [80, 443, 8080, 8443]:
            analysis["connection_type"] = "web"
            analysis["suspicious_score"] = 0.1
        elif remote_port in [22, 23, 21, 25, 110, 143, 993, 995]:
            analysis["connection_type"] = "service"
            analysis["suspicious_score"] = 0.3
        elif remote_port > 49152:  # Puertos dinámicos
            analysis["connection_type"] = "dynamic"
            analysis["suspicious_score"] = 0.6
        else:
            analysis["connection_type"] = "other"
            analysis["suspicious_score"] = 0.4

        return analysis

    def _analyze_udp_connection(self, connection: Dict[str, Any]) -> Dict[str, Any]:
        """Estrategia de análisis para conexiones UDP."""
        analysis = {"protocol_analysis": "udp"}

        remote_port = connection.get("remote_port", 0)

        # DNS queries
        if remote_port == 53:
            analysis["connection_type"] = "dns"
            analysis["suspicious_score"] = 0.1
        # NTP
        elif remote_port == 123:
            analysis["connection_type"] = "ntp"
            analysis["suspicious_score"] = 0.1
        else:
            analysis["connection_type"] = "other_udp"
            analysis["suspicious_score"] = 0.5

        return analysis

    def _analyze_by_port(self, connection: Dict[str, Any], port: int) -> Dict[str, Any]:
        """Estrategia de análisis por puerto."""
        analysis = {}

        # Puertos sospechosos conocidos
        suspicious_ports = {
            1337: "backdoor_common",
            31337: "backdoor_elite",
            12345: "netbus",
            54321: "back_orifice",
            6667: "irc_default",
            6666: "irc_alt",
        }

        if port in suspicious_ports:
            analysis["port_reputation"] = "malicious"
            analysis["port_description"] = suspicious_ports[port]
            analysis["suspicious_score"] = 0.9
        elif port < 1024:
            analysis["port_reputation"] = "system"
            analysis["suspicious_score"] = 0.2
        elif port > 49152:
            analysis["port_reputation"] = "dynamic"
            analysis["suspicious_score"] = 0.4
        else:
            analysis["port_reputation"] = "registered"
            analysis["suspicious_score"] = 0.3

        return analysis

    def _analyze_by_process(
        self, connection: Dict[str, Any], process_name: str
    ) -> Dict[str, Any]:
        """Estrategia de análisis por proceso."""
        analysis = {}

        # Procesos legítimos conocidos
        legitimate_processes = {
            "chrome.exe",
            "firefox.exe",
            "edge.exe",
            "outlook.exe",
            "teams.exe",
            "skype.exe",
            "zoom.exe",
            "discord.exe",
        }

        # Procesos del sistema
        system_processes = {"svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe"}

        if process_name.lower() in legitimate_processes:
            analysis["process_reputation"] = "legitimate"
            analysis["suspicious_score"] = 0.1
        elif process_name.lower() in system_processes:
            analysis["process_reputation"] = "system"
            analysis["suspicious_score"] = 0.2
        elif not process_name or process_name == "":
            analysis["process_reputation"] = "unknown"
            analysis["suspicious_score"] = 0.7
        else:
            analysis["process_reputation"] = "third_party"
            analysis["suspicious_score"] = 0.4

        return analysis

    def _analyze_traffic_pattern(
        self, bytes_sent: int, bytes_recv: int
    ) -> Dict[str, Any]:
        """Estrategia de análisis por patrón de tráfico."""
        analysis = {}

        total_bytes = bytes_sent + bytes_recv
        if total_bytes == 0:
            return {"traffic_pattern": "no_data"}

        upload_ratio = bytes_sent / total_bytes

        # Análisis de ratio de upload
        if upload_ratio > 0.8:
            analysis["traffic_pattern"] = "high_upload"
            analysis["exfiltration_risk"] = "high"
            analysis["suspicious_score"] = 0.8
        elif upload_ratio > 0.6:
            analysis["traffic_pattern"] = "moderate_upload"
            analysis["exfiltration_risk"] = "medium"
            analysis["suspicious_score"] = 0.5
        elif upload_ratio < 0.2:
            analysis["traffic_pattern"] = "download_heavy"
            analysis["exfiltration_risk"] = "low"
            analysis["suspicious_score"] = 0.2
        else:
            analysis["traffic_pattern"] = "balanced"
            analysis["exfiltration_risk"] = "low"
            analysis["suspicious_score"] = 0.3

        # Análisis de volumen
        if total_bytes > 100_000_000:  # 100MB
            analysis["volume_analysis"] = "high_volume"
        elif total_bytes > 10_000_000:  # 10MB
            analysis["volume_analysis"] = "moderate_volume"
        else:
            analysis["volume_analysis"] = "low_volume"

        return analysis

    # ==================== ANÁLISIS DE PATRONES TEMPORALES ====================

    def _update_connection_stats(self, conn_id: str, connection: Dict[str, Any]):
        """Actualiza estadísticas de conexión."""
        now = datetime.now()

        if conn_id not in self.connection_stats:
            self.connection_stats[conn_id] = NetworkStats(
                bytes_sent=connection.get("bytes_sent", 0),
                bytes_received=connection.get("bytes_recv", 0),
                packets_sent=connection.get("packets_sent", 0),
                packets_received=connection.get("packets_recv", 0),
                first_seen=now,
                last_seen=now,
                connection_count=1,
            )
        else:
            stats = self.connection_stats[conn_id]
            stats.bytes_sent = max(stats.bytes_sent, connection.get("bytes_sent", 0))
            stats.bytes_received = max(
                stats.bytes_received, connection.get("bytes_recv", 0)
            )
            stats.packets_sent = max(
                stats.packets_sent, connection.get("packets_sent", 0)
            )
            stats.packets_received = max(
                stats.packets_received, connection.get("packets_recv", 0)
            )
            stats.last_seen = now
            stats.connection_count += 1

    def analyze_temporal_patterns(
        self, time_window_minutes: int = 10
    ) -> Dict[str, Any]:
        """Analiza patrones temporales de conexiones."""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
            recent_connections = [
                entry for entry in self.timeline if entry["timestamp"] > cutoff_time
            ]

            if not recent_connections:
                return {"pattern_type": "no_data"}

            # Análisis de frecuencia por IP
            ip_frequency = defaultdict(int)
            process_frequency = defaultdict(int)

            for entry in recent_connections:
                ip_frequency[entry["remote_ip"]] += 1
                process_frequency[entry["process_name"]] += 1

            # Detectar patrones sospechosos
            analysis = {
                "total_connections": len(recent_connections),
                "unique_ips": len(ip_frequency),
                "unique_processes": len(process_frequency),
                "time_window_minutes": time_window_minutes,
            }

            # Detección de beacons (conexiones regulares)
            beacon_patterns = self._detect_beacon_patterns(recent_connections)
            if beacon_patterns:
                analysis["beacon_detected"] = True
                analysis["beacon_patterns"] = beacon_patterns
                self.metrics["suspicious_patterns"] += 1

            # Detección de ráfagas de conexiones
            burst_patterns = self._detect_connection_bursts(recent_connections)
            if burst_patterns:
                analysis["burst_detected"] = True
                analysis["burst_patterns"] = burst_patterns
                self.metrics["suspicious_patterns"] += 1

            return analysis

        except Exception as e:
            self.logger.error(f"❌ Error analizando patrones temporales: {e}")
            return {"error": str(e)}

    def _detect_beacon_patterns(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detecta patrones de beacon (comunicaciones regulares)."""
        beacon_patterns = []

        # Agrupar por IP y proceso
        grouped = defaultdict(list)
        for conn in connections:
            key = (conn["remote_ip"], conn["process_name"])
            grouped[key].append(conn["timestamp"])

        # Analizar regularidad temporal
        for (ip, process), timestamps in grouped.items():
            if len(timestamps) >= 3:  # Mínimo 3 conexiones
                # Calcular intervalos
                timestamps.sort()
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
                    intervals.append(interval)

                # Calcular regularidad (desviación estándar)
                if len(intervals) >= 2:
                    mean_interval = sum(intervals) / len(intervals)
                    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(
                        intervals
                    )
                    std_dev = variance**0.5

                    # Coeficiente de variación (regularidad)
                    cv = std_dev / max(mean_interval, 1)

                    # Patrón de beacon si es muy regular (CV < 0.3)
                    if cv < 0.3 and len(timestamps) >= 5:
                        beacon_patterns.append(
                            {
                                "remote_ip": ip,
                                "process_name": process,
                                "connection_count": len(timestamps),
                                "mean_interval_seconds": mean_interval,
                                "regularity_score": 1.0 - cv,
                                "confidence": min(0.9, len(timestamps) / 10),
                            }
                        )

        return beacon_patterns

    def _detect_connection_bursts(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detecta ráfagas de conexiones (muchas conexiones en poco tiempo)."""
        burst_patterns = []

        # Agrupar conexiones por minuto
        minute_groups = defaultdict(list)
        for conn in connections:
            minute_key = conn["timestamp"].replace(second=0, microsecond=0)
            minute_groups[minute_key].append(conn)

        # Detectar minutos con muchas conexiones
        for minute, minute_connections in minute_groups.items():
            if len(minute_connections) > self.max_connections:
                # Analizar IPs únicas
                unique_ips = set(conn["remote_ip"] for conn in minute_connections)
                unique_processes = set(
                    conn["process_name"] for conn in minute_connections
                )

                burst_patterns.append(
                    {
                        "timestamp": minute.isoformat(),
                        "connection_count": len(minute_connections),
                        "unique_ips": len(unique_ips),
                        "unique_processes": len(unique_processes),
                        "ips": list(unique_ips)[:10],  # Top 10 IPs
                        "processes": list(unique_processes)[:10],  # Top 10 processes
                        "severity": (
                            "high"
                            if len(minute_connections) > self.max_connections * 2
                            else "medium"
                        ),
                    }
                )

        return burst_patterns

    def analyze_port_usage(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        🔍 TDD #2: Análisis de puertos sospechosos para detección de malware.

        IMPLEMENTACIÓN INTEGRADA desde TDD al NetworkAnalyzer real del antivirus.
        Detecta patrones de comunicación C&C, beaconing y exfiltración de datos.

        Args:
            network_data: Diccionario con información de conexiones de red:
                - process_name: Nombre del proceso
                - connections: Lista de conexiones con puertos

        Returns:
            Diccionario con resultado del análisis:
            {
                'is_suspicious': bool,
                'risk_score': float (0.0-1.0),
                'threat_indicators': list[str],
                'suspicious_ports': list[int],
                'connection_frequency': float,
                'details': dict
            }
        """
        from datetime import datetime, timedelta

        # Inicializar resultado
        result = {
            "is_suspicious": False,
            "risk_score": 0.0,
            "threat_indicators": [],
            "suspicious_ports": [],
            "connection_frequency": 0.0,
            "details": {
                "total_connections": 0,
                "port_risk_breakdown": {},
                "patterns_detected": [],
            },
        }

        connections = network_data.get("connections", [])
        if not connections:
            return result

        result["details"]["total_connections"] = len(connections)

        # Configuración de puertos desde config del antivirus
        port_config = self.config.get(
            "suspicious_ports",
            {
                "high_risk": [1337, 4444, 5555, 31337, 6667, 1234, 12345, 54321],
                "medium_risk": [8080, 9999, 1234, 3128, 8888, 7777],
                "legitimate": [
                    80,
                    443,
                    53,
                    3306,
                    5432,
                    25,
                    110,
                    993,
                    995,
                    143,
                    587,
                    465,
                ],
            },
        )

        high_risk_ports = set(port_config.get("high_risk", []))
        medium_risk_ports = set(port_config.get("medium_risk", []))
        legitimate_ports = set(port_config.get("legitimate", []))

        # Analizar cada conexión
        total_risk_score = 0.0
        suspicious_ports_found = []
        patterns = []

        # Análisis de frecuencia de conexiones (para beaconing)
        if len(connections) > 1:
            timestamps = []
            for conn in connections:
                if "timestamp" in conn:
                    try:
                        if isinstance(conn["timestamp"], str):
                            ts = datetime.fromisoformat(
                                conn["timestamp"].replace("Z", "+00:00")
                            )
                        else:
                            ts = conn["timestamp"]
                        timestamps.append(ts)
                    except:
                        pass

            # Calcular frecuencia si tenemos timestamps
            if len(timestamps) >= 2:
                timestamps.sort()
                time_diff = (max(timestamps) - min(timestamps)).total_seconds()
                if time_diff > 0:
                    result["connection_frequency"] = len(connections) / time_diff

                    # Detectar beaconing (más de 1 conexión cada 60 segundos)
                    if result["connection_frequency"] > (1.0 / 60.0):
                        patterns.append("beaconing_pattern")

        # Analizar puertos en cada conexión
        for conn in connections:
            remote_port = conn.get("remote_port")
            if not remote_port:
                continue

            port_risk = 0.0
            port_category = "unknown"

            # Clasificar puerto por nivel de riesgo
            if remote_port in high_risk_ports:
                port_risk = 0.9
                port_category = "high_risk"
                suspicious_ports_found.append(remote_port)
                if remote_port in [1337, 4444, 5555, 31337]:
                    patterns.append("c2_communication")
            elif remote_port in medium_risk_ports:
                port_risk = 0.6
                port_category = "medium_risk"
                suspicious_ports_found.append(remote_port)
            elif remote_port in legitimate_ports:
                port_risk = 0.1
                port_category = "legitimate"
            else:
                # Puerto desconocido - riesgo bajo-medio
                port_risk = 0.3
                port_category = "unknown"

            total_risk_score += port_risk
            result["details"]["port_risk_breakdown"][remote_port] = {
                "category": port_category,
                "risk": port_risk,
            }

        # Calcular score final
        if connections:
            # Normalizar por número de conexiones, pero dar peso extra a múltiples puertos sospechosos
            base_score = total_risk_score / len(connections)

            # Bonus por múltiples puertos sospechosos diferentes
            unique_suspicious = len(set(suspicious_ports_found))
            if unique_suspicious > 1:
                base_score += 0.2 * (
                    unique_suspicious - 1
                )  # +20% por cada puerto adicional
                patterns.append("multiple_suspicious_ports")

            result["risk_score"] = min(round(base_score, 10), 1.0)

        # Determinar si es sospechoso
        result["suspicious_ports"] = list(set(suspicious_ports_found))
        result["threat_indicators"] = list(set(patterns))
        result["details"]["patterns_detected"] = patterns

        # Umbrales de decisión
        thresholds = self.config.get(
            "thresholds", {"high_risk_score": 0.8, "medium_risk_score": 0.5}
        )
        high_threshold = thresholds.get("high_risk_score", 0.8)
        medium_threshold = thresholds.get("medium_risk_score", 0.5)

        if result["risk_score"] >= high_threshold or "c2_communication" in patterns:
            result["is_suspicious"] = True
        elif result["risk_score"] >= medium_threshold and suspicious_ports_found:
            result["is_suspicious"] = True
        elif "beaconing_pattern" in patterns:
            result["is_suspicious"] = True

        # Log del análisis si es sospechoso
        if result["is_suspicious"]:
            self.logger.warning(
                f"[PORT_ANALYSIS] Proceso sospechoso: {network_data.get('process_name', 'unknown')} "
                f"(Score: {result['risk_score']:.2f}, Puertos: {result['suspicious_ports']})"
            )

        return result

    # ==================== UTILIDADES ====================

    def _is_local_ip(self, ip: str) -> bool:
        """Determina si una IP es local."""
        local_prefixes = [
            "127.",
            "192.168.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "169.254.",
        ]

        return any(ip.startswith(prefix) for prefix in local_prefixes)

    def _is_system_port(self, port: int) -> bool:
        """Determina si un puerto es del sistema."""
        # Puertos comunes del sistema que normalmente no son sospechosos
        system_ports = {53, 80, 443, 123, 443, 993, 995, 587, 465}
        return port in system_ports

    def _is_system_process(self, pid: int) -> bool:
        """Determina si un proceso es del sistema."""
        try:
            process = psutil.Process(pid)
            process_name = process.name().lower()

            system_processes = {
                "system",
                "svchost.exe",
                "explorer.exe",
                "winlogon.exe",
                "csrss.exe",
                "smss.exe",
                "wininit.exe",
                "services.exe",
            }

            return process_name in system_processes
        except:
            return False

    def _analyze_common_ports(
        self, connections: List[Dict[str, Any]]
    ) -> Dict[int, int]:
        """Analiza puertos más comunes en conexiones."""
        port_counts = defaultdict(int)
        for conn in connections:
            port = conn.get("remote_port", 0)
            if port > 0:
                port_counts[port] += 1

        # Retornar top 10 puertos
        return dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    def _analyze_process_patterns(
        self, connections: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Analiza patrones de procesos en conexiones."""
        process_counts = defaultdict(int)
        for conn in connections:
            process = conn.get("process_name", "unknown")
            process_counts[process] += 1

        # Retornar top 10 procesos
        return dict(
            sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )

    def get_connection_summary(self) -> Dict[str, Any]:
        """Obtiene resumen de conexiones analizadas."""
        return {
            "total_unique_connections": len(self.connection_stats),
            "timeline_entries": len(self.timeline),
            "metrics": self.metrics,
            "baseline": getattr(self, "baseline", {}),
            "last_analysis": datetime.now().isoformat(),
        }

    def cleanup_old_data(self, hours: int = 24):
        """Limpia datos antiguos para optimizar memoria."""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Limpiar estadísticas de conexión antiguas
        old_connections = []
        for conn_id, stats in self.connection_stats.items():
            if stats.last_seen < cutoff_time:
                old_connections.append(conn_id)

        for conn_id in old_connections:
            del self.connection_stats[conn_id]

        self.logger.info(f"🧹 Limpiadas {len(old_connections)} conexiones antiguas")


# ==================== TESTING ====================


def main():
    """Función de testing del NetworkAnalyzer."""
    import asyncio

    async def test_analyzer():
        """Test del analizador de red."""
        print("🧪 Testing Network Analyzer...")

        # Configuración de prueba
        config = {
            "network_config": {
                "analysis_window_minutes": 5,
                "max_connections_per_minute": 20,
            }
        }

        # Crear analyzer
        analyzer = NetworkAnalyzer(config)

        # Test inicialización
        success = await analyzer.initialize()
        print(f"✅ Inicialización: {'OK' if success else 'FALLO'}")

        if success:
            # Test captura de conexiones
            connections = analyzer.get_active_connections()
            print(f"🔍 Conexiones detectadas: {len(connections)}")

            # Test análisis temporal
            temporal_analysis = analyzer.analyze_temporal_patterns(5)
            print(
                f"📊 Análisis temporal: {temporal_analysis.get('total_connections', 0)} conexiones"
            )

            # Test resumen
            summary = analyzer.get_connection_summary()
            print(
                f"📋 Resumen: {summary['total_unique_connections']} conexiones únicas"
            )

        print("🏁 Test completado")

    # Ejecutar test
    asyncio.run(test_analyzer())


if __name__ == "__main__":
    main()
