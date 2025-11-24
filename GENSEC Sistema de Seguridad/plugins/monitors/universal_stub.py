"""
Universal Stub Monitor Plugin
=============================

Plugin monitor "stub" que implementa MonitorInterface de forma robusta.
Sirve para garantizar que el sistema tenga al menos un monitor funcional
durante el demo, evitando crashes por monitores complejos que fallan.
"""

import logging
import time
import random
from typing import Dict, Any, Callable
from datetime import datetime

# Importar componentes del core
import sys
from pathlib import Path

# Añadir el directorio raíz al sys.path si no está presente
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import MonitorInterface


class UniversalStubMonitor(BasePlugin, MonitorInterface):
    """
    Monitor universal que simula actividad del sistema.
    Garantiza estabilidad para el demo.
    """

    def __init__(self, config_path: str = None):
        super().__init__("UniversalStubMonitor", str(Path(__file__).parent))
        self.is_monitoring = False
        self.data_callback = None
        self.logger = logging.getLogger(f"plugins.monitors.{self.name}")

    def initialize(self) -> bool:
        """Inicialización del plugin"""
        self.logger.info("[STUB_MONITOR] Inicializado correctamente")
        return True

    def start(self) -> bool:
        """Inicio del plugin"""
        self.logger.info("[STUB_MONITOR] Iniciando stub monitor...")
        self.start_monitoring()
        return True

    def stop(self) -> bool:
        """Parada del plugin"""
        self.stop_monitoring()
        return True

    def get_plugin_info(self) -> Dict[str, Any]:
        """Información del plugin"""
        return {
            "name": "UniversalStubMonitor",
            "version": "1.0.0",
            "description": "Monitor de estabilidad para demo",
            "category": "monitor",
            "type": "system_stub"
        }

    # =================== MONITOR INTERFACE IMPLEMENTATION ===================

    def start_monitoring(self) -> bool:
        """Inicia el monitoreo (simulado)"""
        self.is_monitoring = True
        self.logger.info("[STUB_MONITOR] Monitoreo activo (Simulación)")
        return True

    def stop_monitoring(self) -> bool:
        """Detiene el monitoreo"""
        self.is_monitoring = False
        self.logger.info("[STUB_MONITOR] Monitoreo detenido")
        return True

    def get_current_data(self) -> Dict[str, Any]:
        """
        Retorna datos simulados del sistema para alimentar a los detectores.
        """
        if not self.is_monitoring:
            return {}

        # Simular datos básicos del sistema
        return {
            "timestamp": datetime.now().isoformat(),
            "system_metrics": {
                "cpu_usage": random.uniform(10.0, 45.0),
                "memory_usage": random.uniform(30.0, 60.0),
                "disk_usage": 55.0
            },
            "active_processes": 145,
            "network_connections": 23,
            "status": "nominal"
        }

    def set_data_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Establece callback para notificar nuevos datos"""
        self.data_callback = callback

    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Estadísticas del monitoreo"""
        return {
            "uptime": "always",
            "events_generated": 0,
            "status": "active" if self.is_monitoring else "inactive"
        }

def create_plugin(config_path: str = None) -> UniversalStubMonitor:
    """Factory function"""
    return UniversalStubMonitor(config_path)
