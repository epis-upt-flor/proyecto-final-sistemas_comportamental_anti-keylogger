"""
🔍 Pattern Detector - Detección de Patrones de Red Maliciosos
============================================================

Componente especializado en la detección de patrones específicos de keyloggers y malware.

Implementa:
- Chain of Responsibility: Cadena de detectores especializados
- Strategy Pattern: Diferentes algoritmos de detección por tipo de patrón
- Template Method: Proceso estándar de análisis de patrones
"""

import os
import sys
import json
import time
import logging
import statistics
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path
import math


@dataclass
class BeaconPattern:
    """Representación de un patrón de beacon detectado."""

    process_name: str
    remote_ip: str
    connection_count: int
    mean_interval_seconds: float
    regularity_score: float
    confidence: float
    first_seen: datetime
    last_seen: datetime
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExfiltrationPattern:
    """Representación de un patrón de exfiltración detectado."""

    process_name: str
    remote_ip: str
    total_bytes_sent: int
    upload_ratio: float
    transfer_count: int
    confidence: float
    first_seen: datetime
    last_seen: datetime
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PatternDetector:
    """
    🔍 Detector de patrones maliciosos en comunicaciones de red.

    Implementa Chain of Responsibility para diferentes tipos de detectores:
    1. Beacon Pattern Detector - Comunicaciones regulares C&C
    2. Data Exfiltration Detector - Transferencias sospechosas de datos
    3. DNS Tunnel Detector - Túneles de datos via DNS
    4. Protocol Anomaly Detector - Uso anómalo de protocolos
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("pattern_detector")

        # Configuración de detección
        self.detection_config = config.get("detection_thresholds", {})
        self.beacon_min_count = self.detection_config.get("c2_beacon_min_count", 5)
        self.beacon_regularity = self.detection_config.get("c2_beacon_regularity", 0.8)
        self.exfiltration_ratio = self.detection_config.get(
            "exfiltration_ratio_threshold", 0.8
        )

        # Configuración de análisis
        self.network_config = config.get("network_config", {})
        self.analysis_window = self.network_config.get("analysis_window_minutes", 10)

        # Estado interno - historial de conexiones por proceso/IP
        self.connection_history: Dict[Tuple[str, str], List[Dict[str, Any]]] = (
            defaultdict(list)
        )
        self.beacon_patterns: Dict[str, BeaconPattern] = {}
        self.exfiltration_patterns: Dict[str, ExfiltrationPattern] = {}

        # Métricas
        self.metrics = {
            "beacon_patterns_detected": 0,
            "exfiltration_patterns_detected": 0,
            "dns_tunnels_detected": 0,
            "protocol_anomalies_detected": 0,
            "total_patterns_analyzed": 0,
        }

    async def initialize(self) -> bool:
        """Inicializa el detector de patrones."""
        try:
            self.logger.info("🔍 Inicializando Pattern Detector...")

            # Cargar patrones conocidos si existen
            await self._load_saved_patterns()

            self.logger.info("✅ Pattern Detector inicializado")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error inicializando Pattern Detector: {e}")
            return False

    # ==================== TEMPLATE METHOD ====================

    async def analyze_connection_patterns(
        self, connections: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        🎯 Template Method: Análisis completo de patrones en conexiones.

        Steps:
        1. Actualizar historial de conexiones
        2. Detectar patrones de beacon (Chain of Responsibility)
        3. Detectar patrones de exfiltración
        4. Detectar túneles DNS
        5. Detectar anomalías de protocolo
        """
        try:
            analysis_results = {
                "total_connections_analyzed": len(connections),
                "patterns_detected": [],
                "analysis_timestamp": datetime.now().isoformat(),
            }

            # Step 1: Actualizar historial
            await self._update_connection_history(connections)

            # Step 2: Chain of Responsibility - Detectores especializados
            beacon_patterns = await self._detect_beacon_patterns()
            if beacon_patterns:
                analysis_results["patterns_detected"].extend(beacon_patterns)
                self.metrics["beacon_patterns_detected"] += len(beacon_patterns)

            # Step 3: Detectar exfiltración
            exfiltration_patterns = await self._detect_exfiltration_patterns()
            if exfiltration_patterns:
                analysis_results["patterns_detected"].extend(exfiltration_patterns)
                self.metrics["exfiltration_patterns_detected"] += len(
                    exfiltration_patterns
                )

            # Step 4: Detectar túneles DNS
            dns_patterns = await self._detect_dns_tunnels(connections)
            if dns_patterns:
                analysis_results["patterns_detected"].extend(dns_patterns)
                self.metrics["dns_tunnels_detected"] += len(dns_patterns)

            # Step 5: Detectar anomalías de protocolo
            protocol_anomalies = await self._detect_protocol_anomalies(connections)
            if protocol_anomalies:
                analysis_results["patterns_detected"].extend(protocol_anomalies)
                self.metrics["protocol_anomalies_detected"] += len(protocol_anomalies)

            self.metrics["total_patterns_analyzed"] += 1
            return analysis_results

        except Exception as e:
            self.logger.error(f"❌ Error analizando patrones: {e}")
            return {"error": str(e)}

    # ==================== CHAIN OF RESPONSIBILITY ====================

    async def detect_beacon_pattern(
        self, process_name: str, remote_ip: str
    ) -> Optional[Dict[str, Any]]:
        """
        🎯 Chain Handler 1: Detector de patrones de beacon.

        Los beacons son comunicaciones regulares entre malware y C&C servers.
        """
        try:
            connection_key = (process_name, remote_ip)

            if connection_key not in self.connection_history:
                return None

            connections = self.connection_history[connection_key]

            # Necesitamos suficientes conexiones para analizar patrón
            if len(connections) < self.beacon_min_count:
                return None

            # Extraer timestamps de conexiones
            timestamps = [conn.get("timestamp", datetime.now()) for conn in connections]
            timestamps.sort()

            # Calcular intervalos entre conexiones
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
                intervals.append(interval)

            if len(intervals) < 2:
                return None

            # Analizar regularidad de intervalos
            mean_interval = statistics.mean(intervals)
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0

            # Coeficiente de variación (menor = más regular)
            cv = std_dev / max(mean_interval, 1)
            regularity_score = max(0, 1.0 - cv)

            # Detectar beacon si es suficientemente regular
            if regularity_score >= self.beacon_regularity:
                confidence = min(0.95, regularity_score * (len(connections) / 10))

                beacon = BeaconPattern(
                    process_name=process_name,
                    remote_ip=remote_ip,
                    connection_count=len(connections),
                    mean_interval_seconds=mean_interval,
                    regularity_score=regularity_score,
                    confidence=confidence,
                    first_seen=timestamps[0],
                    last_seen=timestamps[-1],
                    description=f"Beacon regular cada {mean_interval:.1f}s (±{std_dev:.1f}s)",
                )

                # Cachear patrón detectado
                pattern_id = f"{process_name}_{remote_ip}"
                self.beacon_patterns[pattern_id] = beacon

                self.logger.warning(
                    f"🚨 Patrón de beacon detectado: {process_name} -> {remote_ip}"
                )
                return beacon.to_dict()

            return None

        except Exception as e:
            self.logger.error(f"❌ Error detectando beacon: {e}")
            return None

    async def _detect_beacon_patterns(self) -> List[Dict[str, Any]]:
        """Detecta todos los patrones de beacon en el historial."""
        beacon_patterns = []

        for connection_key, connections in self.connection_history.items():
            process_name, remote_ip = connection_key

            pattern = await self.detect_beacon_pattern(process_name, remote_ip)
            if pattern:
                beacon_patterns.append(
                    {
                        "type": "beacon_pattern",
                        "pattern_data": pattern,
                        "severity": "HIGH" if pattern["confidence"] > 0.8 else "MEDIUM",
                    }
                )

        return beacon_patterns

    async def _detect_exfiltration_patterns(self) -> List[Dict[str, Any]]:
        """
        🎯 Chain Handler 2: Detector de patrones de exfiltración de datos.
        """
        exfiltration_patterns = []

        try:
            for connection_key, connections in self.connection_history.items():
                process_name, remote_ip = connection_key

                if len(connections) < 3:  # Mínimo conexiones para patrón
                    continue

                # Analizar transferencias de datos
                total_sent = sum(conn.get("bytes_sent", 0) for conn in connections)
                total_received = sum(
                    conn.get("bytes_received", 0) for conn in connections
                )
                total_bytes = total_sent + total_received

                if total_bytes == 0:
                    continue

                # Calcular ratio de upload
                upload_ratio = total_sent / total_bytes

                # Detectar exfiltración si hay mucho upload
                if (
                    upload_ratio >= self.exfiltration_ratio and total_sent > 1024
                ):  # Mínimo 1KB
                    confidence = min(
                        0.9, upload_ratio + (total_sent / 1000000)
                    )  # Factor por volumen

                    exfiltration = ExfiltrationPattern(
                        process_name=process_name,
                        remote_ip=remote_ip,
                        total_bytes_sent=total_sent,
                        upload_ratio=upload_ratio,
                        transfer_count=len(connections),
                        confidence=confidence,
                        first_seen=min(
                            conn.get("timestamp", datetime.now())
                            for conn in connections
                        ),
                        last_seen=max(
                            conn.get("timestamp", datetime.now())
                            for conn in connections
                        ),
                        description=f"Exfiltración: {total_sent:,} bytes ({upload_ratio:.1%} upload)",
                    )

                    # Cachear patrón
                    pattern_id = f"{process_name}_{remote_ip}"
                    self.exfiltration_patterns[pattern_id] = exfiltration

                    exfiltration_patterns.append(
                        {
                            "type": "data_exfiltration",
                            "pattern_data": exfiltration.to_dict(),
                            "severity": "CRITICAL" if total_sent > 100000 else "HIGH",
                        }
                    )

                    self.logger.warning(
                        f"🚨 Exfiltración detectada: {process_name} -> {remote_ip}"
                    )

            return exfiltration_patterns

        except Exception as e:
            self.logger.error(f"❌ Error detectando exfiltración: {e}")
            return []

    async def _detect_dns_tunnels(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        🎯 Chain Handler 3: Detector de túneles DNS.
        """
        dns_patterns = []

        try:
            # Filtrar conexiones DNS (puerto 53)
            dns_connections = [
                conn
                for conn in connections
                if conn.get("remote_port") == 53 or conn.get("protocol") == "DNS"
            ]

            if not dns_connections:
                return dns_patterns

            # Agrupar por proceso
            process_dns = defaultdict(list)
            for conn in dns_connections:
                process_name = conn.get("process_name", "unknown")
                process_dns[process_name].append(conn)

            # Analizar cada proceso
            for process_name, process_connections in process_dns.items():
                if len(process_connections) < 10:  # Necesitamos muchas consultas DNS
                    continue

                # Calcular estadísticas
                query_count = len(process_connections)
                time_span = self._calculate_time_span(process_connections)

                if time_span == 0:
                    continue

                queries_per_minute = query_count / max(time_span / 60, 1)

                # Túnel DNS si hay muchas consultas por minuto
                if queries_per_minute > 20:  # Umbral ajustable
                    # Analizar entropía de dominios (si disponible)
                    domains = [
                        conn.get("domain", "")
                        for conn in process_connections
                        if conn.get("domain")
                    ]
                    entropy_score = (
                        self._calculate_domain_entropy_average(domains)
                        if domains
                        else 0
                    )

                    confidence = min(
                        0.8, (queries_per_minute / 100) + (entropy_score / 5)
                    )

                    dns_patterns.append(
                        {
                            "type": "dns_tunnel",
                            "pattern_data": {
                                "process_name": process_name,
                                "query_count": query_count,
                                "queries_per_minute": queries_per_minute,
                                "time_span_seconds": time_span,
                                "average_domain_entropy": entropy_score,
                                "confidence": confidence,
                                "description": f"Túnel DNS: {query_count} consultas en {time_span:.1f}s",
                            },
                            "severity": "HIGH" if queries_per_minute > 50 else "MEDIUM",
                        }
                    )

                    self.logger.warning(f"🚨 Túnel DNS detectado: {process_name}")

            return dns_patterns

        except Exception as e:
            self.logger.error(f"❌ Error detectando túneles DNS: {e}")
            return []

    async def _detect_protocol_anomalies(
        self, connections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        🎯 Chain Handler 4: Detector de anomalías de protocolo.
        """
        protocol_anomalies = []

        try:
            # Agrupar conexiones por proceso y protocolo
            process_protocols = defaultdict(lambda: defaultdict(list))

            for conn in connections:
                process_name = conn.get("process_name", "unknown")
                protocol = conn.get("protocol", "TCP")
                port = conn.get("remote_port", 0)

                process_protocols[process_name][protocol].append(conn)

            # Analizar cada proceso
            for process_name, protocols in process_protocols.items():
                anomaly_score = 0.0
                anomalies_found = []

                for protocol, protocol_connections in protocols.items():
                    # Analizar puertos para este protocolo
                    ports = [
                        conn.get("remote_port", 0) for conn in protocol_connections
                    ]
                    unique_ports = set(ports)

                    # Anomalía 1: HTTP en puertos no estándar
                    if protocol == "TCP":
                        non_standard_http = [
                            p for p in unique_ports if p not in [80, 443, 8080, 8443]
                        ]
                        if len(non_standard_http) > 3:
                            anomaly_score += 0.3
                            anomalies_found.append(
                                f"HTTP en puertos no estándar: {non_standard_http[:5]}"
                            )

                    # Anomalía 2: Muchos puertos diferentes
                    if len(unique_ports) > 10:
                        anomaly_score += 0.2
                        anomalies_found.append(
                            f"Múltiples puertos: {len(unique_ports)} diferentes"
                        )

                    # Anomalía 3: Puertos sospechosos conocidos
                    suspicious_ports = {1337, 31337, 12345, 54321, 6667, 6666}
                    used_suspicious = unique_ports.intersection(suspicious_ports)
                    if used_suspicious:
                        anomaly_score += 0.4
                        anomalies_found.append(
                            f"Puertos sospechosos: {list(used_suspicious)}"
                        )

                # Si hay suficientes anomalías, reportar
                if anomaly_score > 0.4:
                    confidence = min(0.9, anomaly_score)

                    protocol_anomalies.append(
                        {
                            "type": "protocol_anomaly",
                            "pattern_data": {
                                "process_name": process_name,
                                "anomaly_score": anomaly_score,
                                "anomalies_detected": anomalies_found,
                                "protocols_used": list(protocols.keys()),
                                "unique_ports_count": sum(
                                    len(
                                        set(
                                            conn.get("remote_port", 0) for conn in conns
                                        )
                                    )
                                    for conns in protocols.values()
                                ),
                                "confidence": confidence,
                                "description": f"Anomalías de protocolo: {', '.join(anomalies_found[:3])}",
                            },
                            "severity": "HIGH" if anomaly_score > 0.7 else "MEDIUM",
                        }
                    )

                    self.logger.warning(f"🚨 Anomalía de protocolo: {process_name}")

            return protocol_anomalies

        except Exception as e:
            self.logger.error(f"❌ Error detectando anomalías de protocolo: {e}")
            return []

    # ==================== UTILIDADES DE ANÁLISIS ====================

    async def _update_connection_history(self, connections: List[Dict[str, Any]]):
        """Actualiza el historial de conexiones para análisis de patrones."""
        try:
            cutoff_time = datetime.now() - timedelta(minutes=self.analysis_window)

            # Agregar nuevas conexiones al historial
            for conn in connections:
                process_name = conn.get("process_name", "unknown")
                remote_ip = conn.get("remote_ip", "")

                if process_name and remote_ip:
                    connection_key = (process_name, remote_ip)

                    # Agregar conexión con timestamp
                    conn_with_timestamp = {
                        **conn,
                        "timestamp": conn.get("timestamp", datetime.now()),
                    }

                    self.connection_history[connection_key].append(conn_with_timestamp)

            # Limpiar conexiones antiguas
            for connection_key in list(self.connection_history.keys()):
                # Filtrar conexiones recientes
                recent_connections = [
                    conn
                    for conn in self.connection_history[connection_key]
                    if conn.get("timestamp", datetime.now()) > cutoff_time
                ]

                if recent_connections:
                    self.connection_history[connection_key] = recent_connections
                else:
                    # Eliminar clave si no hay conexiones recientes
                    del self.connection_history[connection_key]

        except Exception as e:
            self.logger.error(f"❌ Error actualizando historial de conexiones: {e}")

    def _calculate_time_span(self, connections: List[Dict[str, Any]]) -> float:
        """Calcula el span de tiempo de una lista de conexiones en segundos."""
        if not connections:
            return 0.0

        timestamps = [conn.get("timestamp", datetime.now()) for conn in connections]
        if len(timestamps) < 2:
            return 0.0

        return (max(timestamps) - min(timestamps)).total_seconds()

    def _calculate_domain_entropy_average(self, domains: List[str]) -> float:
        """Calcula la entropía promedio de una lista de dominios."""
        try:
            if not domains:
                return 0.0

            entropies = []
            for domain in domains:
                entropy = self._calculate_single_domain_entropy(domain)
                entropies.append(entropy)

            return statistics.mean(entropies)

        except Exception:
            return 0.0

    def _calculate_single_domain_entropy(self, domain: str) -> float:
        """Calcula la entropía de Shannon de un dominio."""
        try:
            from collections import Counter

            if not domain:
                return 0.0

            # Contar frecuencia de caracteres
            char_counts = Counter(domain.lower())
            domain_length = len(domain)

            # Calcular entropía de Shannon
            entropy = 0.0
            for count in char_counts.values():
                probability = count / domain_length
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            return entropy

        except Exception:
            return 0.0

    # ==================== PERSISTENCIA ====================

    async def _load_saved_patterns(self):
        """Carga patrones guardados anteriormente."""
        try:
            patterns_file = Path("cache/saved_patterns.json")

            if patterns_file.exists():
                with open(patterns_file, "r", encoding="utf-8") as f:
                    saved_data = json.load(f)

                # Cargar beacon patterns
                beacon_data = saved_data.get("beacon_patterns", {})
                for pattern_id, pattern_dict in beacon_data.items():
                    # Convertir timestamps de vuelta a datetime
                    pattern_dict["first_seen"] = datetime.fromisoformat(
                        pattern_dict["first_seen"]
                    )
                    pattern_dict["last_seen"] = datetime.fromisoformat(
                        pattern_dict["last_seen"]
                    )

                    self.beacon_patterns[pattern_id] = BeaconPattern(**pattern_dict)

                # Cargar exfiltration patterns
                exfiltration_data = saved_data.get("exfiltration_patterns", {})
                for pattern_id, pattern_dict in exfiltration_data.items():
                    pattern_dict["first_seen"] = datetime.fromisoformat(
                        pattern_dict["first_seen"]
                    )
                    pattern_dict["last_seen"] = datetime.fromisoformat(
                        pattern_dict["last_seen"]
                    )

                    self.exfiltration_patterns[pattern_id] = ExfiltrationPattern(
                        **pattern_dict
                    )

                self.logger.info(
                    f"📋 Patrones cargados: {len(self.beacon_patterns)} beacons, {len(self.exfiltration_patterns)} exfiltraciones"
                )

        except Exception as e:
            self.logger.error(f"❌ Error cargando patrones: {e}")

    async def save_patterns(self):
        """Guarda patrones detectados en disco."""
        try:
            patterns_data = {
                "beacon_patterns": {},
                "exfiltration_patterns": {},
                "saved_at": datetime.now().isoformat(),
            }

            # Guardar beacon patterns
            for pattern_id, beacon in self.beacon_patterns.items():
                pattern_dict = beacon.to_dict()
                # Convertir datetime a string para JSON
                pattern_dict["first_seen"] = beacon.first_seen.isoformat()
                pattern_dict["last_seen"] = beacon.last_seen.isoformat()
                patterns_data["beacon_patterns"][pattern_id] = pattern_dict

            # Guardar exfiltration patterns
            for pattern_id, exfiltration in self.exfiltration_patterns.items():
                pattern_dict = exfiltration.to_dict()
                pattern_dict["first_seen"] = exfiltration.first_seen.isoformat()
                pattern_dict["last_seen"] = exfiltration.last_seen.isoformat()
                patterns_data["exfiltration_patterns"][pattern_id] = pattern_dict

            # Escribir archivo
            cache_dir = Path("cache")
            cache_dir.mkdir(exist_ok=True)

            with open(cache_dir / "saved_patterns.json", "w", encoding="utf-8") as f:
                json.dump(patterns_data, f, indent=2, ensure_ascii=False)

            self.logger.info("💾 Patrones guardados en disco")

        except Exception as e:
            self.logger.error(f"❌ Error guardando patrones: {e}")

    # ==================== API PÚBLICA ====================

    def get_pattern_summary(self) -> Dict[str, Any]:
        """Obtiene resumen de patrones detectados."""
        return {
            "beacon_patterns_count": len(self.beacon_patterns),
            "exfiltration_patterns_count": len(self.exfiltration_patterns),
            "active_connections_tracked": len(self.connection_history),
            "metrics": self.metrics,
            "last_analysis": datetime.now().isoformat(),
        }

    def get_active_beacon_patterns(self) -> List[Dict[str, Any]]:
        """Obtiene patrones de beacon activos."""
        return [beacon.to_dict() for beacon in self.beacon_patterns.values()]

    def get_active_exfiltration_patterns(self) -> List[Dict[str, Any]]:
        """Obtiene patrones de exfiltración activos."""
        return [
            exfiltration.to_dict()
            for exfiltration in self.exfiltration_patterns.values()
        ]

    def cleanup_old_patterns(self, hours: int = 24):
        """Limpia patrones antiguos para optimizar memoria."""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        # Limpiar beacon patterns antiguos
        old_beacons = []
        for pattern_id, beacon in self.beacon_patterns.items():
            if beacon.last_seen < cutoff_time:
                old_beacons.append(pattern_id)

        for pattern_id in old_beacons:
            del self.beacon_patterns[pattern_id]

        # Limpiar exfiltration patterns antiguos
        old_exfiltrations = []
        for pattern_id, exfiltration in self.exfiltration_patterns.items():
            if exfiltration.last_seen < cutoff_time:
                old_exfiltrations.append(pattern_id)

        for pattern_id in old_exfiltrations:
            del self.exfiltration_patterns[pattern_id]

        if old_beacons or old_exfiltrations:
            self.logger.info(
                f"🧹 Limpiados {len(old_beacons)} beacons y {len(old_exfiltrations)} exfiltraciones antiguos"
            )


# ==================== TESTING ====================


def main():
    """Función de testing del PatternDetector."""
    import asyncio

    async def test_pattern_detector():
        """Test del detector de patrones."""
        print("🧪 Testing Pattern Detector...")

        # Configuración de prueba
        config = {
            "detection_thresholds": {
                "c2_beacon_min_count": 3,
                "c2_beacon_regularity": 0.7,
                "exfiltration_ratio_threshold": 0.7,
            },
            "network_config": {"analysis_window_minutes": 10},
        }

        # Crear detector
        detector = PatternDetector(config)

        # Test inicialización
        success = await detector.initialize()
        print(f"✅ Inicialización: {'OK' if success else 'FALLO'}")

        if success:
            # Crear conexiones de prueba para beacon
            test_connections = []
            base_time = datetime.now()

            for i in range(10):
                conn = {
                    "process_name": "suspicious.exe",
                    "remote_ip": "185.220.100.240",
                    "remote_port": 8080,
                    "protocol": "TCP",
                    "bytes_sent": 1000,
                    "bytes_received": 100,
                    "timestamp": base_time
                    + timedelta(seconds=i * 30),  # Conexión cada 30s
                }
                test_connections.append(conn)

            # Test análisis de patrones
            results = await detector.analyze_connection_patterns(test_connections)
            print(
                f"🔍 Patrones analizados: {results.get('total_connections_analyzed', 0)}"
            )
            print(
                f"🚨 Patrones detectados: {len(results.get('patterns_detected', []))}"
            )

            # Test detección de beacon específico
            beacon_result = await detector.detect_beacon_pattern(
                "suspicious.exe", "185.220.100.240"
            )
            if beacon_result:
                print(
                    f"📡 Beacon detectado: confianza {beacon_result.get('confidence', 0):.2f}"
                )

            # Test resumen
            summary = detector.get_pattern_summary()
            print(f"📊 Beacons: {summary['beacon_patterns_count']}")
            print(f"📊 Exfiltraciones: {summary['exfiltration_patterns_count']}")

        print("🏁 Test completado")

    # Ejecutar test
    asyncio.run(test_pattern_detector())


if __name__ == "__main__":
    main()
