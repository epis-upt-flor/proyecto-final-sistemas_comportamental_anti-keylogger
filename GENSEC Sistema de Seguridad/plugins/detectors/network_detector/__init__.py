"""
🌐 Network Detector Plugin - Auto-registro
==========================================

Este plugin se especializa en el análisis de patrones de red maliciosos para detectar:
- Comunicaciones C&C (Command and Control)
- Exfiltración de datos
- Patrones de beacon periódicos
- Túneles DNS maliciosos
- Anomalías de protocolo

El plugin implementa múltiples patrones de diseño:
- Observer: Monitoreo continuo de conexiones
- Strategy: Algoritmos intercambiables de detección
- Template Method: Proceso estándar de análisis
- Chain of Responsibility: Cadena de analizadores especializados

Auto-registro automático cuando se importa el módulo.
"""

from .plugin import NetworkDetectorPlugin


def get_plugin_class():
    """
    Función requerida para el auto-registro del plugin.

    Returns:
        type: La clase NetworkDetectorPlugin para instanciación
    """
    return NetworkDetectorPlugin


def get_plugin_info():
    """
    Información del plugin para el sistema de gestión.

    Returns:
        dict: Metadatos del plugin incluyendo nombre, versión y categoría
    """
    return {
        "name": "network_detector",
        "version": "1.0.0",
        "category": "detectors",
        "description": "Detector de patrones de red maliciosos",
        "author": "Anti-Keylogger Team",
        "dependencies": ["psutil", "requests"],
        "events_subscribed": [
            "network_connection_established",
            "network_data_transferred",
            "dns_query_made",
            "scan_requested",
        ],
        "events_published": [
            "c2_communication_detected",
            "data_exfiltration_detected",
            "beacon_pattern_detected",
            "malicious_domain_accessed",
        ],
    }


# Auto-registro al importar
__all__ = ["NetworkDetectorPlugin", "get_plugin_class", "get_plugin_info"]
