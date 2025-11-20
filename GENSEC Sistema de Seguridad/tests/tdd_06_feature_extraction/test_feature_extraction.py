"""
TDD Test #6: Extracción de Features para ML
Priority: #6 (12/20 points)

Este test valida la extracción de características relevantes para
los modelos de Machine Learning del sistema antivirus.

Funcionalidad: FeatureExtractor.extract_features()
"""

import unittest
import sys
import os

# Agregar el directorio raíz al path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, root_dir)

# GREEN PHASE: Habilitar importación
from plugins.detectors.ml_detector.feature_extractor import FeatureExtractor


class TestFeatureExtraction(unittest.TestCase):
    """Test para extracción de features ML"""

    def setUp(self):
        """Setup para cada test"""
        self.extractor = FeatureExtractor()  # GREEN phase habilitado

    def test_feature_extraction(self):
        """
        RED PHASE: Este test debe fallar inicialmente

        Test que verifica que se extraigan features correctos
        para el análisis ML de procesos sospechosos
        """
        # Datos de proceso de prueba
        process_data = {
            "name": "suspicious.exe",
            "cpu_usage": 85.2,
            "memory_usage": 512.0,
            "api_calls": ["SetWindowsHookExW", "GetAsyncKeyState"],
            "network_connections": [{"port": 4444, "direction": "outbound"}],
            "file_operations": ["create", "write", "delete"],
        }

        # GREEN PHASE: Implementar funcionalidad real
        features = self.extractor.extract_features(process_data)

        # Verificar que se extraigan features esperados
        expected_features = [
            "cpu_usage_raw_normalized",
            "memory_usage_raw_normalized",
            "hooking_apis_count_normalized",
            "network_risk_score_normalized",
            "file_operations_count_normalized",
        ]

        for feature in expected_features:
            self.assertIn(feature, features)
            self.assertIsInstance(features[feature], (int, float))

    def test_api_features_extraction(self):
        """
        Test específico para extracción de features de APIs
        """
        api_calls = [
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "CreateFileW",
            "WriteFile",
        ]

        # GREEN PHASE: Implementar funcionalidad real
        features = self.extractor.extract_api_features(api_calls)
        self.assertIn("hooking_apis_count", features)
        self.assertIn("keylogging_apis_ratio", features)
        self.assertEqual(features["hooking_apis_count"], 2)

    def test_behavioral_features_extraction(self):
        """
        Test para extracción de features de comportamiento
        """
        behavior_data = {
            "process_lifetime": 3600,  # segundos
            "cpu_spikes": [85, 92, 88, 90],
            "memory_growth": [100, 150, 200, 250],  # MB
            "network_activity": {"connections": 5, "data_sent": 1024},
        }

        # GREEN PHASE: Implementar funcionalidad real
        features = self.extractor.extract_behavioral_features(behavior_data)
        self.assertIn("process_stability_score", features)
        self.assertIn("resource_anomaly_score", features)
        self.assertIn("network_activity_score", features)

    def test_feature_normalization(self):
        """
        Test para normalización de features
        """
        raw_features = {"cpu_usage": 85.5, "memory_usage": 512.0, "api_count": 150}

        # GREEN PHASE: Implementar funcionalidad real
        normalized = self.extractor.normalize_features(raw_features)

        # Verificar que los valores estén normalizados [0, 1]
        for key, value in normalized.items():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_feature_selection(self):
        """
        Test para selección de features más relevantes
        """
        all_features = {
            "cpu_usage": 0.85,
            "memory_usage": 0.51,
            "api_hooking_score": 0.92,
            "network_risk_score": 0.88,
            "file_operations_count": 0.34,
            "process_name_entropy": 0.67,
        }

        # GREEN PHASE: Implementar funcionalidad real
        selected = self.extractor.select_top_features(all_features, top_k=3)
        self.assertEqual(len(selected), 3)
        self.assertIn("api_hooking_score", selected)  # Debe ser top feature


if __name__ == "__main__":
    unittest.main()
