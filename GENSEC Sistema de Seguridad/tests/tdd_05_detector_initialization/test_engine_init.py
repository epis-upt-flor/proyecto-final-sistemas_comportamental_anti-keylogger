"""
TDD Test #5: Inicialización del Motor de Detección
Priority: 🎖️ #5 (15/20 points)

Este test valida que el motor de detección se inicialice correctamente
y sea la base sólida para todos los otros detectores.

Funcionalidad: DetectorEngine.__init__()
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
from core.detector_engine import DetectorEngine


class TestDetectorInitialization(unittest.TestCase):
    """Test para inicialización del motor de detección"""

    def setUp(self):
        """Setup para cada test"""
        pass

    def test_detector_initialization(self):
        """
        RED PHASE: Este test debe fallar inicialmente

        Test que verifica que el DetectorEngine se inicialice correctamente
        con la configuración proporcionada
        """
        # Configuración de prueba
        test_config = {
            "ml_models_path": "models/",
            "plugins_enabled": True,
            "logging_level": "INFO",
            "detection_threshold": 0.8,
        }

        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine(config=test_config)
        self.assertTrue(engine.is_initialized)
        self.assertEqual(engine.config["detection_threshold"], 0.8)
        self.assertTrue(engine.plugins_loaded)

    def test_initialization_without_config(self):
        """
        Test que verifica inicialización con configuración por defecto
        """
        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine()
        self.assertTrue(engine.is_initialized)
        self.assertIsNotNone(engine.default_config)
        self.assertEqual(engine.config["detection_threshold"], 0.7)  # Default

    def test_ml_models_loading(self):
        """
        Test para verificar que los modelos ML se cargen correctamente
        """
        config = {
            "ml_models_path": "models/",
            "models": ["keylogger_model_large_20250918_112840.onnx"],
        }

        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine(config=config)
        self.assertTrue(engine.ml_models_loaded)
        self.assertIn("keylogger_model_large_20250918_112840", engine.loaded_models)
        self.assertIsNotNone(engine.get_model("keylogger_model_large_20250918_112840"))

    def test_plugin_system_initialization(self):
        """
        Test para verificar que el sistema de plugins se inicialice
        """
        config = {
            "plugins_enabled": True,
            "plugin_directories": ["plugins/detectors/", "plugins/handlers/"],
        }

        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine(config=config)
        self.assertTrue(
            engine.plugins_loaded
        )  # Cambiado para usar la propiedad correcta
        self.assertGreater(len(engine.plugin_manager.loaded_plugins), 0)

        # Verificar plugins específicos
        expected_plugins = ["ml_detector", "behavior_detector", "network_detector"]
        for plugin in expected_plugins:
            self.assertIn(plugin, engine.plugin_manager.loaded_plugins)

    def test_configuration_validation(self):
        """
        Test para validar configuración incorrecta
        """
        invalid_configs = [
            {"detection_threshold": 1.5},  # Threshold > 1.0
            {"ml_models_path": "/nonexistent/path"},  # Path inexistente
            {"logging_level": "INVALID_LEVEL"},  # Nivel inválido
        ]

        for invalid_config in invalid_configs:
            with self.subTest(config=invalid_config):
                # GREEN PHASE: Funcionalidad implementada
                with self.assertRaises(ValueError):
                    DetectorEngine(config=invalid_config)

    def test_event_bus_initialization(self):
        """
        Test para verificar que el bus de eventos se inicialice
        """
        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine()
        self.assertIsNotNone(engine.event_bus)
        self.assertTrue(engine.event_bus.is_running)

        # Verificar que se pueden registrar eventos
        result = engine.event_bus.register_handler("test_event", lambda x: x)
        self.assertTrue(result)

    def test_graceful_shutdown(self):
        """
        Test para verificar que el engine se cierre correctamente
        """
        # GREEN PHASE: Funcionalidad implementada
        engine = DetectorEngine()
        engine.initialize()

        # Verificar shutdown limpio
        result = engine.shutdown()
        self.assertTrue(result)
        self.assertFalse(engine.is_running)
        self.assertFalse(engine.event_bus.is_running)


if __name__ == "__main__":
    unittest.main()
