"""
ML Detector Plugin - Auto-registro
=================================

Auto-registro del plugin ML Detector en el sistema.
"""

from .plugin import MLDetectorPlugin, create_plugin

# Auto-registro usando decorador
import sys
from pathlib import Path

# Añadir el directorio raíz al sys.path si no está presente
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.plugin_registry import PluginRegistry

# Registro manual del plugin
plugin_registry = PluginRegistry()

def register_ml_detector():
    """Función de registro del plugin ML Detector"""
    return create_plugin()

# Realizar el registro automáticamente
try:
    plugin_registry.register_plugin(MLDetectorPlugin, 'ml_detector', 'detectors')
except Exception as e:
    logger = __import__('logging').getLogger(__name__)
    logger.warning(f"No se pudo auto-registrar MLDetectorPlugin: {e}")

# Información del plugin para discovery
PLUGIN_INFO = {
    'name': 'ml_detector',
    'version': '1.0.0',
    'description': 'Detector de keyloggers usando Machine Learning con modelos ONNX',
    'category': 'detectors',
    'priority': 1,
    'dependencies': ['onnxruntime', 'numpy', 'pandas', 'scikit-learn'],
    'author': 'Sistema Anti-Keylogger Unificado',
    'factory_function': create_plugin
}

__all__ = ['MLDetectorPlugin', 'create_plugin', 'PLUGIN_INFO']