"""
TDD Test #7: Consenso de Múltiples Detectores
Priority: #7 (12/20 points)

Este test valida el sistema de consenso que combina resultados
de múltiples detectores usando técnicas de ensemble ML.

Funcionalidad: ConsensusEngine.combine_detectors()
"""

import unittest
import sys
import os

# Agregar el directorio raíz del proyecto al path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

# GREEN PHASE: Ahora importamos la implementación
from core.consensus_engine import ConsensusEngine


class TestConsensus(unittest.TestCase):
    """Test para sistema de consenso de detectores"""

    def setUp(self):
        """Setup para cada test"""
        self.consensus = ConsensusEngine()  # GREEN phase - Ya implementado

    def test_multiple_detectors_consensus(self):
        """
        RED PHASE: Este test debe fallar inicialmente

        Test que verifica que el consenso entre múltiples detectores
        funcione correctamente y mejore la precisión
        """
        # Resultados de diferentes detectores
        detector_results = {
            "ml_detector": {"risk_level": "HIGH", "score": 0.92, "confidence": 0.85},
            "behavior_detector": {
                "risk_level": "MEDIUM",
                "score": 0.65,
                "confidence": 0.78,
            },
            "network_detector": {
                "risk_level": "HIGH",
                "score": 0.88,
                "confidence": 0.90,
            },
            "api_detector": {"risk_level": "HIGH", "score": 0.95, "confidence": 0.93},
        }

        # GREEN PHASE: Ahora probamos la implementación
        consensus_result = self.consensus.combine_detectors(detector_results)

        # El consenso debe ser HIGH (3 de 4 detectores)
        self.assertEqual(consensus_result["final_risk_level"], "HIGH")
        self.assertGreater(consensus_result["consensus_score"], 0.8)
        self.assertGreater(consensus_result["confidence"], 0.85)

    def test_weighted_consensus(self):
        """
        Test para consenso ponderado según confiabilidad de detectores
        """
        detector_results = {
            "ml_detector": {"risk_level": "HIGH", "score": 0.92, "weight": 0.4},
            "behavior_detector": {"risk_level": "LOW", "score": 0.25, "weight": 0.2},
            "network_detector": {"risk_level": "MEDIUM", "score": 0.55, "weight": 0.3},
            "api_detector": {"risk_level": "HIGH", "score": 0.88, "weight": 0.1},
        }

        result = self.consensus.weighted_consensus(detector_results)
        # ML detector tiene más peso, resultado debe tender a HIGH
        self.assertEqual(result["final_risk_level"], "HIGH")

    def test_consensus_with_conflicting_results(self):
        """
        Test para manejar resultados conflictivos entre detectores
        """
        conflicting_results = {
            "detector_1": {"risk_level": "HIGH", "score": 0.95},
            "detector_2": {"risk_level": "LOW", "score": 0.15},
            "detector_3": {"risk_level": "MEDIUM", "score": 0.55},
            "detector_4": {"risk_level": "LOW", "score": 0.20},
        }

        result = self.consensus.resolve_conflicts(conflicting_results)
        # Debe manejar el conflicto y dar un resultado coherente
        self.assertIn(result["final_risk_level"], ["LOW", "MEDIUM", "HIGH"])
        self.assertIn("conflict_resolution_method", result)

    def test_minimum_detectors_threshold(self):
        """
        Test para validar umbral mínimo de detectores activos
        """
        insufficient_results = {"detector_1": {"risk_level": "HIGH", "score": 0.95}}

        # Debe requerir al menos 2 detectores para consenso confiable
        with self.assertRaises(ValueError):
            self.consensus.combine_detectors(insufficient_results, min_detectors=2)

    def test_ensemble_ml_consensus(self):
        """
        Test para consenso usando técnicas ML de ensemble
        """
        ml_predictions = [
            {
                "detector": "random_forest",
                "prediction": [0.1, 0.2, 0.7],
            },  # LOW, MED, HIGH
            {"detector": "svm", "prediction": [0.05, 0.15, 0.8]},
            {"detector": "neural_net", "prediction": [0.2, 0.3, 0.5]},
        ]

        result = self.consensus.ensemble_consensus(ml_predictions, method="voting")
        self.assertEqual(result["predicted_class"], "HIGH")
        self.assertIn("ensemble_confidence", result)


if __name__ == "__main__":
    unittest.main()
