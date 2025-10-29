"""
Behavior Detector Plugin - Auto-registro
========================================

Auto-registro del plugin Behavior Detector en el sistema.
"""

from .plugin import BehaviorDetectorPlugin, create_plugin

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

def register_behavior_detector():
    """Función de registro del plugin Behavior Detector"""
    return create_plugin()

# Realizar el registro automáticamente
try:
    plugin_registry.register_plugin(BehaviorDetectorPlugin, 'behavior_detector', 'detectors')
except Exception as e:
    logger = __import__('logging').getLogger(__name__)
    logger.warning(f"No se pudo auto-registrar BehaviorDetectorPlugin: {e}")

# Información del plugin para discovery
PLUGIN_INFO = {
    'name': 'behavior_detector',
    'version': '1.0.0',
    'description': 'Detector de keyloggers usando análisis heurístico de comportamiento',
    'category': 'detectors',
    'priority': 2,
    'dependencies': ['threading', 'concurrent.futures'],
    'author': 'Sistema Anti-Keylogger Unificado',
    'factory_function': create_plugin
}

__all__ = ['BehaviorDetectorPlugin', 'create_plugin', 'PLUGIN_INFO']