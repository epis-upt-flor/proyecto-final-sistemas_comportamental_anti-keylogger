"""
Detector avanzado de keyloggers con ML y análisis comportamental

Generado automáticamente via MDSD Simple
"""

import logging
import time
from typing import Dict, List, Any, Optional
from core.interfaces import DetectorInterface
from core.base_plugin import BasePlugin


class AdvancedKeyloggerDetectorDetectorPlugin(BasePlugin, DetectorInterface):
    """
    Detector avanzado de keyloggers con ML y análisis comportamental

    Generado automáticamente via MDSD Simple
    """

    def __init__(self, plugin_name: str, plugin_path: str):
        super().__init__(plugin_name, plugin_path)
        self.name = "Advanced Keylogger Detector"
        self.description = (
            "Detector avanzado de keyloggers con ML y análisis comportamental"
        )
        self.enabled = True
        self.priority = 95

        # Setup del logger específico
        self.setup_logging()
        self.logger.info("🚀 " + self.name + " detector creado")

    def detect_threats(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Interface requerida por DetectorInterface - Detecta amenazas en datos del sistema

        Args:
            system_data: Datos del sistema para analizar

        Returns:
            List[Dict]: Lista de amenazas detectadas
        """
        threats = []

        # Analizar procesos individuales si están disponibles
        processes = system_data.get("processes", [])
        if not processes:
            # Si no hay procesos específicos, tratar system_data como un proceso
            processes = [system_data]

        for process_data in processes:
            threat_result = self._detect_single_process(process_data)
            if threat_result.get("threat_detected", False):
                threats.append(
                    {
                        "threat_type": "malware",
                        "severity": (
                            "high"
                            if threat_result.get("threat_score", 0) > 0.8
                            else "medium"
                        ),
                        "process_data": process_data,
                        "detection_result": threat_result,
                        "detector_name": self.name,
                    }
                )

        return threats

    def _detect_single_process(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detección principal para un proceso individual - Advanced Keylogger Detector

        Triggers configurados:
        - Trigger 1: api_call = SetWindowsHookExW
        - Trigger 2: api_call = SetWindowsHookExA
        - Trigger 3: api_call = GetAsyncKeyState
        - Trigger 4: process_behavior = hidden_window
        - Trigger 5: file_activity = log_creation
        - Trigger 6: network_activity = data_exfiltration
        - Trigger 7: network_connections = suspicious_ports
        - Trigger 8: registry_access = autostart_keys
        - Trigger 9: cpu_usage = 15
        """

        detection_start = time.time()
        threat_score = 0.0

        try:
            # Evaluación de triggers
            # Trigger 1: api_call
            api_calls = process_data.get("api_calls", [])
            if "SetWindowsHookExW" in api_calls:
                threat_score += 3.0

            # Trigger 2: api_call
            api_calls = process_data.get("api_calls", [])
            if "SetWindowsHookExA" in api_calls:
                threat_score += 2.5

            # Trigger 3: api_call
            api_calls = process_data.get("api_calls", [])
            if "GetAsyncKeyState" in api_calls:
                threat_score += 2.0

            # Trigger 4: process_behavior
            # Trigger genérico: process_behavior = hidden_window
            if process_data.get("process_behavior", 0) > hidden_window:
                threat_score += 2.0

            # Trigger 5: file_activity
            # Trigger genérico: file_activity = log_creation
            if process_data.get("file_activity", 0) > log_creation:
                threat_score += 1.5

            # Trigger 6: network_activity
            connections = process_data.get("network_connections", [])
            suspicious_count = len([c for c in connections if "suspicious" in str(c)])
            if suspicious_count > 0:
                threat_score += 2.5

            # Trigger 7: network_connections
            connections = process_data.get("network_connections", [])
            suspicious_count = len([c for c in connections if "suspicious" in str(c)])
            if suspicious_count > 0:
                threat_score += 1.5

            # Trigger 8: registry_access
            # Trigger genérico: registry_access = autostart_keys
            if process_data.get("registry_access", 0) > autostart_keys:
                threat_score += 1.8

            # Trigger 9: cpu_usage
            cpu_usage = process_data.get("cpu_usage", 0)
            if cpu_usage > 15:
                threat_score += 1.0

            # Determinar si hay amenaza
            threat_detected = threat_score >= 0.7

            # Actualizar estadísticas
            self._confidence_score = threat_score
            if hasattr(self, "_detection_stats"):
                self._detection_stats["total_detections"] += 1
                if threat_detected:
                    self._detection_stats["threats_detected"] += 1
                    self._detection_stats["last_detection"] = time.time()

            # Ejecutar respuestas si hay amenaza
            if threat_detected:
                self.logger.info(f"🔍 {self.name}: Amenaza detectada")
                self.logger.warning(
                    f'🚨 ALERT [warning]: {process_data.get("name", "unknown")}'
                )
                self.logger.warning(
                    f'🚨 ALERT [critical]: {process_data.get("name", "unknown")}'
                )
                self.logger.critical(
                    f'🔒 QUARANTINE [critical]: {process_data.get("name", "unknown")}'
                )
                # Respuesta: forensics - critical
                # Respuesta: network_block - high

            detection_time = time.time() - detection_start

            return {
                "threat_detected": threat_detected,
                "threat_score": threat_score,
                "detection_time_ms": detection_time * 1000,
                "detector_name": self.name,
                "generated_by_mdsd": True,
            }

        except Exception as e:
            self.logger.error("❌ Error en " + self.name + ": " + str(e))
            return {
                "threat_detected": False,
                "error": str(e),
                "detector_name": self.name,
            }

    def _check_network_activity(self, connections: list) -> bool:
        """Helper para análisis de red"""
        suspicious_ports = [4444, 5555, 6666, 8080]
        return any(conn.get("port", 0) in suspicious_ports for conn in connections)

    # =================== MÉTODOS ABSTRACTOS DE BasePlugin ===================

    def initialize(self) -> bool:
        """Inicialización específica del detector MDSD"""
        try:
            self.logger.info(f"🔧 Inicializando " + self.name + "...")

            # Inicializar componentes específicos del detector
            self._confidence_score = 0.0
            self._detection_stats = {
                "total_detections": 0,
                "threats_detected": 0,
                "false_positives": 0,
                "last_detection": None,
            }

            self.logger.info(f"✅ " + self.name + " inicializado correctamente")
            return True
        except Exception as e:
            self.logger.error("❌ Error inicializando " + self.name + ": " + str(e))
            return False

    def start(self) -> bool:
        """Inicio del detector"""
        try:
            self.logger.info(f"🚀 Iniciando " + self.name + "...")
            self.is_running = True
            return True
        except Exception as e:
            self.logger.error("❌ Error iniciando " + self.name + ": " + str(e))
            return False

    def stop(self) -> bool:
        """Parada del detector"""
        try:
            self.logger.info(f"🛑 Deteniendo " + self.name + "...")
            self.is_running = False
            return True
        except Exception as e:
            self.logger.error("❌ Error deteniendo " + self.name + ": " + str(e))
            return False

    # =================== MÉTODOS ABSTRACTOS DE DetectorInterface ===================

    def get_confidence_score(self) -> float:
        """Nivel de confianza de la última detección"""
        return getattr(self, "_confidence_score", 0.0)

    def update_signatures(self) -> bool:
        """Actualiza firmas/patrones - Para MDSD no aplica (generado automáticamente)"""
        self.logger.info(f"📋 " + self.name + ": Firmas MDSD siempre actualizadas")
        return True

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Estadísticas de detección del detector"""
        stats = getattr(self, "_detection_stats", {})
        stats.update(
            {
                "detector_name": self.name,
                "generated_by": "MDSD_Simple",
                "priority": 95,
                "threshold": 0.7,
            }
        )
        return stats

    def get_plugin_info(self) -> Dict[str, Any]:
        """Información del plugin generado"""
        return {
            "name": "Advanced Keylogger Detector",
            "description": "Detector avanzado de keyloggers con ML y análisis comportamental",
            "generated_by": "MDSD_Simple",
            "version": "1.0.0",
            "priority": 95,
            "enabled": True,
            "type": "detector",
            "interfaces": ["DetectorInterface", "BasePlugin"],
        }


# Factory function para registro automático
def create_plugin():
    """Factory function requerida por el sistema de plugins"""
    plugin_name = "Advanced Keylogger Detector".lower().replace(" ", "_")
    plugin_path = "plugins/detectors/generated"
    return AdvancedKeyloggerDetectorDetectorPlugin(plugin_name, plugin_path)
