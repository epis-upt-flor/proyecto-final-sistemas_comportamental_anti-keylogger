"""
Keylogger Detector Plugin Package
=================================

Plugin especializado en detección de keyloggers basado en análisis de keyloggers reales.

Keyloggers analizados para crear este detector:
- Harem.c (C keylogger básico)  
- Ghost_Writer.cs (C# keylogger avanzado)
- EncryptedKeylogger.py (Python keylogger cifrado)
"""

from .keylogger_detector import KeyloggerDetector, create_plugin

__version__ = "2.0.0"
__author__ = "KrCrimson"
__description__ = "Detector especializado de keyloggers basado en análisis comportamental"

# Plugin metadata for automatic discovery
PLUGIN_INFO = {
    "name": "keylogger_detector",
    "version": __version__,
    "description": __description__,
    "author": __author__,
    "category": "detector",
    "priority": "high",
    "factory_function": create_plugin
}

# Export main components
__all__ = [
    'KeyloggerDetector',
    'create_plugin', 
    'PLUGIN_INFO'
]