"""
Plugin Auto-Registration System
==============================

Sistema automático de registro de plugins para UNIFIED_ANTIVIRUS.
Este archivo se encarga de registrar todos los plugins disponibles
en el sistema usando el PluginRegistry.
"""

import sys
import os
import logging
from pathlib import Path

# Asegurar que el directorio actual está en sys.path
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from core.plugin_registry import PluginRegistry

logger = logging.getLogger(__name__)


def register_all_plugins():
    """
    Registra automáticamente todos los plugins del sistema.
    
    Esta función busca y registra plugins de todas las categorías:
    - Detectors (ML, Behavior, Network)
    - Monitors (File, Network, Process) 
    - Interfaces (UI, Web API)
    """
    
    registry = PluginRegistry()
    logger.info("🔌 Iniciando registro automático de plugins...")
    
    # =================== DETECTOR PLUGINS ===================
    
    # ML Detector Plugin - Solo importar si existe
    try:
        from plugins.detectors.ml_detector.plugin import MLDetectorPlugin
        ml_detector = MLDetectorPlugin()
        registry.register_plugin(
            plugin_class=MLDetectorPlugin,
            plugin_name="ml_detector",
            category="detectors"
        )
        logger.info("✅ MLDetectorPlugin registrado")
    except (ImportError, AttributeError) as e:
        logger.warning(f"⚠️  No se pudo importar MLDetectorPlugin: {e}")
    
    # Behavior Detector Plugin - Saltamos por ahora (falta __init__.py)
    try:
        from plugins.detectors.behavior_detector import BehaviorDetectorPlugin
        behavior_detector = BehaviorDetectorPlugin()
        registry.register_plugin(
            plugin_class=BehaviorDetectorPlugin,
            plugin_name="behavior_detector", 
            category="detectors"
        )
        logger.info("✅ BehaviorDetectorPlugin registrado")
    except ImportError as e:
        logger.warning(f"⚠️  No se pudo importar BehaviorDetectorPlugin: {e}")
    
    try:
        # Network Detector Plugin
        from plugins.detectors.network_detector import NetworkDetectorPlugin
        registry.register_plugin(
            plugin_class=NetworkDetectorPlugin,
            plugin_name="network_detector",
            category="detectors"
        )
        logger.info("✅ NetworkDetectorPlugin registrado")
    except ImportError as e:
        logger.warning(f"⚠️  No se pudo importar NetworkDetectorPlugin: {e}")
    
    # Keylogger Detector Plugin - ESPECIALIZADO EN KEYLOGGERS
    try:
        from plugins.detectors.keylogger_detector.keylogger_detector import KeyloggerDetector
        registry.register_plugin(
            plugin_class=KeyloggerDetector,
            plugin_name="keylogger_detector",
            category="detectors"
        )
        logger.info("✅ KeyloggerDetector registrado (especializado)")
    except ImportError as e:
        logger.warning(f"⚠️  No se pudo importar KeyloggerDetector: {e}")
    
    # =================== MONITOR PLUGINS ===================
    
    try:
        # File Monitor Plugin (importar desde __init__.py)
        from plugins.monitors.file_monitor import FileMonitorPlugin
        file_monitor = FileMonitorPlugin()
        registry.register_plugin(
            plugin_class=FileMonitorPlugin,
            plugin_name="file_monitor",
            category="monitors"
        )
        logger.info("✅ FileMonitorPlugin registrado")
    except (ImportError, Exception) as e:
        logger.warning(f"⚠️  No se pudo importar FileMonitorPlugin: {e}")
    
    try:
        # Network Monitor Plugin (importar desde __init__.py)
        from plugins.monitors.network_monitor import NetworkMonitorPlugin
        network_monitor = NetworkMonitorPlugin()
        registry.register_plugin(
            plugin_class=NetworkMonitorPlugin,
            plugin_name="network_monitor",
            category="monitors"
        )
        logger.info("✅ NetworkMonitorPlugin registrado")
    except (ImportError, Exception) as e:
        logger.warning(f"⚠️  No se pudo importar NetworkMonitorPlugin: {e}")
    
    try:
        # Process Monitor Plugin (importar desde __init__.py)
        from plugins.monitors.process_monitor import ProcessMonitorPlugin
        process_monitor = ProcessMonitorPlugin()
        registry.register_plugin(
            plugin_class=ProcessMonitorPlugin,
            plugin_name="process_monitor",
            category="monitors"
        )
        logger.info("✅ ProcessMonitorPlugin registrado")
    except (ImportError, Exception) as e:
        logger.warning(f"⚠️  No se pudo importar ProcessMonitorPlugin: {e}")
    
    # =================== INTERFACE PLUGINS ===================
    
    try:
        # Tkinter UI Plugin
        from plugins.interfaces.tkinter_ui import TkinterUIPlugin
        registry.register_plugin(
            plugin_class=TkinterUIPlugin,
            plugin_name="tkinter_ui",
            category="interfaces"
        )
        logger.info("✅ TkinterUIPlugin registrado")
    except ImportError as e:
        logger.warning(f"⚠️  No se pudo importar TkinterUIPlugin: {e}")
    
    # =================== RESUMEN DE REGISTRO ===================
    
    stats = registry.get_statistics()
    logger.info("📊 Registro de plugins completado:")
    logger.info(f"   - Total de plugins registrados: {stats['total_plugins']}")
    logger.info(f"   - Detectores: {stats['by_category'].get('detectors', 0)}")
    logger.info(f"   - Monitores: {stats['by_category'].get('monitors', 0)}")
    logger.info(f"   - Interfaces: {stats['by_category'].get('interfaces', 0)}")
    
    return stats


def get_registered_plugins_info():
    """
    Obtiene información detallada de todos los plugins registrados.
    
    Returns:
        Dict con información completa de plugins por categoría
    """
    registry = PluginRegistry()
    
    info = {
        'detectors': [],
        'monitors': [], 
        'interfaces': [],
        'total_count': 0
    }
    
    # Obtener plugins por categoría
    for category in ['detectors', 'monitors', 'interfaces']:
        plugins = registry.get_plugins_by_category(category)
        
        # El método puede retornar una lista o dict, normalizamos
        if isinstance(plugins, list):
            plugins_dict = {plugin: registry.get_plugin_info(plugin) for plugin in plugins if registry.get_plugin_info(plugin)}
        else:
            plugins_dict = plugins
        
        for plugin_name, plugin_info in plugins_dict.items():
            plugin_data = {
                'name': plugin_name,
                'class_name': plugin_info.get('class').__name__ if plugin_info.get('class') else 'Unknown',
                'category': category,
                'auto_discovered': plugin_info.get('auto_discovered', False),
                'description': getattr(plugin_info.get('class'), '__doc__', 'Sin descripción') or 'Sin descripción'
            }
            info[category].append(plugin_data)
            info['total_count'] += 1
    
    return info


def test_plugin_registration():
    """
    Función de test para verificar el registro de plugins.
    """
    print("=== TEST: Sistema de Registro de Plugins ===")
    
    try:
        # Ejecutar registro automático
        stats = register_all_plugins()
        
        # Verificar que se registraron plugins
        if stats['total_plugins'] > 0:
            print(f"✅ Registro exitoso: {stats['total_plugins']} plugins registrados")
            
            # Mostrar detalles por categoría
            for category, count in stats['by_category'].items():
                if count > 0:
                    print(f"   - {category.title()}: {count} plugins")
            
            # Obtener información detallada
            detailed_info = get_registered_plugins_info()
            
            print("\n📋 Plugins registrados por categoría:")
            
            for category in ['detectors', 'monitors', 'interfaces']:
                plugins_in_category = detailed_info[category]
                if plugins_in_category:
                    print(f"\n🔧 {category.upper()}:")
                    for plugin in plugins_in_category:
                        print(f"   • {plugin['name']} ({plugin['class_name']})")
                        desc = plugin['description'].split('\n')[0][:60]
                        if len(desc) < len(plugin['description'].split('\n')[0]):
                            desc += "..."
                        print(f"     {desc}")
            
            print(f"\n🎯 Total: {detailed_info['total_count']} plugins disponibles")
            print("=== REGISTRO COMPLETADO EXITOSAMENTE ===")
            return True
        else:
            print("❌ No se registraron plugins")
            return False
    
    except Exception as e:
        print(f"❌ Error en registro: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Configurar logging básico para tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Ejecutar test de registro
    test_plugin_registration()