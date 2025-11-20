"""
TDD Test #8: Detección de Umbral de Memoria
Priority: #8 (11/20 points)

Este test valida la detección de procesos que exceden umbrales
sospechosos de uso de memoria, típico de malware.

Funcionalidad: MemoryMonitor.analyze_memory_usage()
"""

import unittest
import sys
import os

# Agregar el directorio raíz del proyecto al path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

# GREEN PHASE: Ahora importamos la implementación
from core.memory_monitor import MemoryMonitor


class TestMemoryThreshold(unittest.TestCase):
    """Test para detección de umbrales de memoria"""

    def setUp(self):
        """Setup para cada test"""
        self.monitor = MemoryMonitor()  # GREEN phase - Ya implementado

    def test_memory_threshold_detection(self):
        """
        RED PHASE: Este test debe fallar inicialmente

        Test que verifica que procesos que exceden umbrales de memoria
        sean detectados como sospechosos
        """
        # Casos de alto uso de memoria
        high_memory_scenarios = [
            {"process": "malware.exe", "memory_mb": 2048, "threshold": 1024},
            {"process": "keylogger.exe", "memory_mb": 1500, "threshold": 1024},
            {"process": "suspicious.exe", "memory_mb": 3072, "threshold": 1024},
        ]

        for scenario in high_memory_scenarios:
            with self.subTest(scenario=scenario):
                # GREEN PHASE: Ahora probamos la implementación
                result = self.monitor.analyze_memory_usage(
                    scenario["process"],
                    scenario["memory_mb"],
                    scenario["threshold"]
                )
                self.assertEqual(result["risk_level"], "HIGH")
                self.assertGreaterEqual(result["suspicion_score"], 0.8)

    def test_normal_memory_usage_not_flagged(self):
        """
        Test que verifica que uso normal de memoria no sea flaggeado
        """
        normal_memory_scenarios = [
            {"process": "notepad.exe", "memory_mb": 25, "threshold": 1024},
            {"process": "chrome.exe", "memory_mb": 512, "threshold": 1024},
            {"process": "explorer.exe", "memory_mb": 128, "threshold": 1024},
        ]

        for scenario in normal_memory_scenarios:
            with self.subTest(scenario=scenario):
                result = self.monitor.analyze_memory_usage(
                    scenario["process"],
                    scenario["memory_mb"],
                    scenario["threshold"]
                )
                self.assertIn(result["risk_level"], ["LOW", "MEDIUM"])
                self.assertLess(result["suspicion_score"], 0.6)

    def test_memory_leak_detection(self):
        """
        Test para detectar memory leaks sospechosos
        """
        # Simular crecimiento continuo de memoria
        memory_history = [
            {"time": "10:00", "memory_mb": 100},
            {"time": "10:01", "memory_mb": 150},
            {"time": "10:02", "memory_mb": 200},
            {"time": "10:03", "memory_mb": 280},
            {"time": "10:04", "memory_mb": 350},
            {"time": "10:05", "memory_mb": 450},  # Crecimiento continuo
        ]

        result = self.monitor.detect_memory_leak("suspicious.exe", memory_history)
        self.assertTrue(result["leak_detected"])
        self.assertEqual(result["leak_severity"], "HIGH")

    def test_memory_spike_detection(self):
        """
        Test para detectar picos anómalos de memoria
        """
        memory_with_spike = [
            {"time": "10:00", "memory_mb": 50},
            {"time": "10:01", "memory_mb": 48},
            {"time": "10:02", "memory_mb": 52},
            {"time": "10:03", "memory_mb": 2048},  # Pico anómalo
            {"time": "10:04", "memory_mb": 55},
        ]

        result = self.monitor.detect_memory_anomalies("test.exe", memory_with_spike)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(result["anomaly_type"], "SUDDEN_SPIKE")

    def test_adaptive_threshold_adjustment(self):
        """
        Test para ajuste adaptativo de umbrales basado en el sistema
        """
        system_info = {
            "total_memory_gb": 16,
            "available_memory_gb": 8,
            "system_load": "normal",
        }

        adjusted_threshold = self.monitor.calculate_adaptive_threshold(system_info)
        # En un sistema con 16GB, el umbral debe ser más alto
        self.assertGreater(adjusted_threshold, 1024)
        self.assertLess(adjusted_threshold, 4096)  # Pero razonable

    def test_process_memory_classification(self):
        """
        Test para clasificar procesos por patrones de uso de memoria
        """
        memory_patterns = {
            "stable_low": [100, 102, 98, 105, 95],  # Estable y bajo
            "stable_high": [1500, 1520, 1480, 1510, 1490],  # Estable pero alto
            "growing": [100, 200, 300, 400, 500],  # Creciendo
            "volatile": [100, 500, 150, 800, 200],  # Volátil
        }

        for pattern_name, memory_data in memory_patterns.items():
            with self.subTest(pattern=pattern_name):
                classification = self.monitor.classify_memory_pattern(memory_data)
                self.assertIn("pattern_type", classification)
                self.assertIn("risk_assessment", classification)


if __name__ == "__main__":
    unittest.main()
