"""
Keylogger Detector Plugin Entry Point
===================================

Entry point para el detector especializado de keyloggers.
"""

import logging
logger = logging.getLogger(__name__)

# Importación independiente para evitar conflictos de autodescubrimiento
import sys
import os
sys.path.append(os.path.dirname(__file__))
from keylogger_detector import KeyloggerDetector

# Para autodescubrimiento del sistema
class KeyloggerDetectorPlugin(KeyloggerDetector):
    """Plugin wrapper para autodescubrimiento del sistema"""
    
    def __init__(self, config=None):
        """Inicializar con configuración por defecto si no se proporciona"""
        if config is None:
            config = {
                "enabled": True,
                "detection_sensitivity": "medium",
                "detection_threshold": 0.6,
                "monitor_hooks": True,
                "monitor_files": True,
                "monitor_stealth": True,
                "auto_response": True,
                "log_level": "info"
            }
            logger.info("[KEYLOGGER_DETECTOR] Usando configuración por defecto")
        
        super().__init__(config)

# Función de factory para crear el plugin
def create_plugin(config=None):
    """Crear una instancia del plugin"""
    if config is None:
        config = {
            "enabled": True,
            "detection_sensitivity": "medium",
            "detection_threshold": 0.6,
            "log_level": "info"
        }
    return KeyloggerDetectorPlugin(config)