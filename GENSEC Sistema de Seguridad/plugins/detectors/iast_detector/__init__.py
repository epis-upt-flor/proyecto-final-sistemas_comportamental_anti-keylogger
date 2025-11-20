#!/usr/bin/env python3
"""
Inicializador del paquete IAST Detector
=====================================
"""

from .plugin import IASTDetectorPlugin, create_plugin
from .iast_engine import IASTSelfProtectionEngine

__all__ = [
    'IASTDetectorPlugin',
    'IASTSelfProtectionEngine', 
    'create_plugin'
]

__version__ = "1.0.0"
__author__ = "Antivirus Security Team"
__description__ = "IAST Self-Protection & Keylogger Detection Engine"