"""
Base Plugin - Template Method Pattern
=====================================

Define el ciclo de vida común para todos los plugins del sistema.
Este es el patrón Template Method en acción.
"""

import logging
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class BasePlugin(ABC):
    """
    Clase base que implementa Template Method Pattern.

    Define el algoritmo común (template) para todos los plugins:
    1. setup_logging()    - Común para todos
    2. load_config()      - Común para todos
    3. initialize()       - Específico por plugin (abstract)
    4. start()           - Específico por plugin (abstract)
    5. stop()            - Común para todos
    6. cleanup()         - Común para todos
    """

    def __init__(self, plugin_name: str, plugin_path: str):
        self.plugin_name = plugin_name
        self.plugin_path = Path(plugin_path)
        self.config = {}
        self.is_running = False
        self.logger = None

    # =================== TEMPLATE METHOD ===================
    def activate(self) -> bool:
        """
        Método template que define el algoritmo completo.
        Los pasos comunes están implementados, los específicos son abstractos.
        """
        try:
            # Pasos comunes (implementados aquí)
            self.setup_logging()
            self.load_config()

            # Pasos específicos (implementados por cada plugin)
            if not self.initialize():
                return False

            if not self.start():
                return False

            self.is_running = True
            self.logger.info(f"✅ Plugin '{self.plugin_name}' activado exitosamente")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error activando plugin '{self.plugin_name}': {e}")
            return False

    def deactivate(self) -> bool:
        """Template method para desactivar plugin"""
        try:
            if self.is_running:
                self.stop()  # Específico por plugin

            self.cleanup()  # Común
            self.is_running = False
            self.logger.info(f"🔴 Plugin '{self.plugin_name}' desactivado")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error desactivando plugin: {e}")
            return False

    # =================== MÉTODOS COMUNES ===================
    def setup_logging(self):
        """Configuración común de logging para todos los plugins"""
        self.logger = logging.getLogger(f"plugin.{self.plugin_name}")

        # Handler específico para este plugin
        log_file = Path("logs") / f"{self.plugin_name}.log"
        log_file.parent.mkdir(exist_ok=True)

        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def load_config(self):
        """Carga configuración común desde config.json del plugin"""
        config_file = self.plugin_path / "config.json"

        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
                self.logger.info(f"📄 Configuración cargada desde {config_file}")
            except Exception as e:
                self.logger.warning(f"⚠️ Error cargando config: {e}")
                self.config = {}
        else:
            self.logger.info("📄 No se encontró config.json, usando defaults")
            self.config = {}

    def cleanup(self):
        """Limpieza común para todos los plugins"""
        # Cerrar handlers de logging
        if self.logger:
            for handler in self.logger.handlers[:]:
                handler.close()
                self.logger.removeHandler(handler)

    # =================== MÉTODOS ABSTRACTOS ===================
    @abstractmethod
    def initialize(self) -> bool:
        """
        Inicialización específica del plugin.
        Cada tipo de plugin implementa su lógica aquí.
        """
        pass

    @abstractmethod
    def start(self) -> bool:
        """
        Inicio específico del plugin.
        Detectores inician monitoreo, UI inicia interfaz, etc.
        """
        pass

    @abstractmethod
    def stop(self) -> bool:
        """
        Parada específica del plugin.
        Cada plugin maneja su parada de manera apropiada.
        """
        pass

    @abstractmethod
    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Información específica del plugin.
        Usado por Registry Pattern para catalogar plugins.
        """
        pass

    # =================== MÉTODOS DE CONSULTA ===================
    def get_name(self) -> str:
        """Nombre del plugin"""
        return self.plugin_name

    def get_status(self) -> str:
        """Estado actual del plugin"""
        return "running" if self.is_running else "stopped"

    def get_config(self) -> Dict[str, Any]:
        """Configuración actual del plugin"""
        return self.config.copy()


class PluginInterface(ABC):
    """
    Interface adicional para plugins que necesitan comunicación
    con otros componentes (Observer Pattern)
    """

    @abstractmethod
    def on_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Maneja eventos del event bus"""
        pass

    @abstractmethod
    def publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publica eventos al event bus"""
        pass
