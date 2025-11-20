"""
Core Module - Unified Antivirus System
=====================================

Módulo central que exporta todas las clases principales
del sistema unificado anti-keylogger.
"""

from .engine import UnifiedAntivirusEngine
from .plugin_manager import PluginManager
from .plugin_registry import PluginRegistry, register_plugin
from .base_plugin import BasePlugin, PluginInterface
from .event_bus import EventBus, Event, event_bus, subscribe_to
from .interfaces import (
    DetectorInterface,
    MonitorInterface, 
    InterfacePluginInterface,
    HandlerInterface,
    ConfigurableInterface,
    PluginHealthInterface,
    ThreatInfo,
    SystemData
)

# Versión del sistema
__version__ = "1.0.0"
__author__ = "Anti-Keylogger Team"

# Exportaciones principales
__all__ = [
    # Core classes
    'UnifiedAntivirusEngine',
    'PluginManager', 
    'PluginRegistry',
    'BasePlugin',
    'EventBus',
    'Event',
    
    # Interfaces
    'DetectorInterface',
    'MonitorInterface',
    'InterfacePluginInterface', 
    'HandlerInterface',
    'ConfigurableInterface',
    'PluginInterface',
    'PluginHealthInterface',
    
    # Utilities
    'ThreatInfo',
    'SystemData',
    
    # Singletons
    'event_bus',
    
    # Decorators
    'register_plugin',
    'subscribe_to'
]