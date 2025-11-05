"""
TDD Test #4: Monitoreo de CPU para Detección de Anomalías
Priority: 🏅 #4 (15/20 points)

Este test valida la detección de procesos con uso anómalo de CPU,
típico de keyloggers y malware que monitorea constantemente.

Funcionalidad: ResourceMonitor.analyze_cpu_usage()
"""

import unittest
import sys
import os

# Agregar el directorio del proyecto UNIFIED_ANTIVIRUS al path
unified_antivirus_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)
sys.path.insert(0, unified_antivirus_path)

# GREEN PHASE: Importación implementada
from core.resource_monitor import ResourceMonitor


class TestCPUMonitoring(unittest.TestCase):
    """Test para monitoreo de CPU y detección de anomalías"""

    def setUp(self):
        """Setup para cada test"""
        self.monitor = ResourceMonitor()  # GREEN phase - implementado

    def test_high_cpu_process_flagged_as_suspicious(self):
        """
        RED PHASE: Este test debe fallar inicialmente

        Test que verifica que procesos con alto uso de CPU
        sean flaggeados como sospechosos
        """
        # Casos de alto uso de CPU
        high_cpu_scenarios = [
            {"process": "malware.exe", "cpu_usage": 95.5, "duration": 300},
            {"process": "keylogger.exe", "cpu_usage": 89.2, "duration": 600},
            {"process": "suspicious.exe", "cpu_usage": 82.1, "duration": 120},
        ]

        for scenario in high_cpu_scenarios:
            with self.subTest(scenario=scenario):
                # GREEN PHASE: Funcionalidad implementada
                result = self.monitor.analyze_cpu_usage(
                    scenario["process"], scenario["cpu_usage"], scenario["duration"]
                )
                self.assertEqual(result["risk_level"], "HIGH")
                self.assertGreater(result["suspicion_score"], 0.8)

    def test_normal_cpu_usage_not_flagged(self):
        """
        Test que verifica que uso normal de CPU no sea flaggeado
        """
        normal_cpu_scenarios = [
            {"process": "notepad.exe", "cpu_usage": 2.1, "duration": 60},
            {"process": "chrome.exe", "cpu_usage": 15.3, "duration": 300},
            {"process": "explorer.exe", "cpu_usage": 5.8, "duration": 1800},
        ]

        for scenario in normal_cpu_scenarios:
            with self.subTest(scenario=scenario):
                # GREEN PHASE: Funcionalidad implementada
                result = self.monitor.analyze_cpu_usage(
                    scenario["process"], scenario["cpu_usage"], scenario["duration"]
                )
                self.assertIn(result["risk_level"], ["LOW", "MEDIUM"])
                self.assertLess(result["suspicion_score"], 0.6)

    def test_cpu_spike_detection(self):
        """
        Test para detectar picos anómalos de CPU
        """
        # Simular histórico de CPU con pico anómalo
        cpu_history = [
            {"time": "10:00", "cpu": 5.2},
            {"time": "10:01", "cpu": 4.8},
            {"time": "10:02", "cpu": 6.1},
            {"time": "10:03", "cpu": 92.5},  # Pico anómalo
            {"time": "10:04", "cpu": 5.9},
        ]

        # GREEN PHASE: Funcionalidad implementada
        result = self.monitor.detect_cpu_anomalies("test_process.exe", cpu_history)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(result["anomaly_type"], "SUDDEN_SPIKE")

    def test_sustained_high_cpu_detection(self):
        """
        Test para detectar uso sostenido y anómalo de CPU
        """
        # CPU alto por período extendido (típico de keyloggers)
        sustained_high_cpu = [
            {"time": f"10:{i:02d}", "cpu": 85.0 + (i % 5)}
            for i in range(10)  # 10 minutos de CPU alto
        ]

        # GREEN PHASE: Funcionalidad implementada
        result = self.monitor.analyze_sustained_cpu_usage(
            "potential_keylogger.exe", sustained_high_cpu
        )
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertTrue(result["sustained_anomaly"])

    def test_cpu_threshold_configuration(self):
        """
        Test para configuración de umbrales de CPU
        """
        # GREEN PHASE: Funcionalidad implementada
        # Verificar que se pueden configurar umbrales
        self.monitor.set_cpu_threshold("suspicious", 80.0)
        self.monitor.set_cpu_threshold("high_risk", 90.0)

        threshold_config = self.monitor.get_cpu_thresholds()
        self.assertEqual(threshold_config["suspicious"], 80.0)
        self.assertEqual(threshold_config["high_risk"], 90.0)


if __name__ == "__main__":
    unittest.main()
