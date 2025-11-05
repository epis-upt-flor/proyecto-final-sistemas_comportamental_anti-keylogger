"""
Plugin Manager - Abstract Factory + Facade Pattern
================================================

Gestor principal que coordina todos los plugins del sistema.
Implementa Abstract Factory para crear familias de plugins
y Facade para simplificar la interfaz compleja.
"""

import logging
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path
from .base_plugin import BasePlugin
from .plugin_registry import PluginRegistry
from .event_bus import event_bus, Event

logger = logging.getLogger(__name__)


class PluginManager:
    """
    Plugin Manager - Facade que simplifica la gestión de plugins.

    Combina múltiples patrones:
    - Abstract Factory: Crea familias de plugins
    - Facade: Simplifica interfaz compleja
    - Template Method: Usa ciclo de vida común
    - Observer: Conecta plugins al event bus

    Es el punto central de control para todos los plugins.
    """

    def __init__(self, base_path: str = "plugins"):
        self.base_path = Path(base_path)
        self.registry = PluginRegistry()
        self.active_plugins: Dict[str, BasePlugin] = {}
        self.plugin_threads: Dict[str, threading.Thread] = {}
        self._lock = threading.RLock()

        # Configurar logging
        self.logger = logging.getLogger("PluginManager")

        logger.info("🎛️ PluginManager inicializado")

    # =================== FACTORY METHODS ===================
    def discover_and_load_plugins(self) -> bool:
        """
        Factory method que descubre y carga todos los plugins disponibles.

        Returns:
            True si el proceso fue exitoso
        """
        try:
            self.logger.info("🔍 Iniciando descubrimiento de plugins...")

            # Descubrir plugins automáticamente
            discovered = self.registry.discover_plugins(self.base_path)

            if discovered == 0:
                self.logger.warning("⚠️ No se encontraron plugins")
                return False

            self.logger.info(
                f"✅ Descubrimiento completado: {discovered} plugins encontrados"
            )
            return True

        except Exception as e:
            self.logger.error(f"❌ Error en descubrimiento de plugins: {e}")
            return False

    def create_plugin_family(self, category: str) -> Dict[str, BasePlugin]:
        """
        Abstract Factory method que crea una familia de plugins de una categoría.

        Args:
            category: Categoría de plugins (detectors, interfaces, etc.)

        Returns:
            Diccionario con instancias de plugins de la categoría
        """
        family = {}

        try:
            plugin_names = self.registry.get_plugins_by_category(category)

            for name in plugin_names:
                plugin = self.create_plugin(name)
                if plugin:
                    family[name] = plugin

            self.logger.info(f"🏭 Familia '{category}' creada: {len(family)} plugins")
            return family

        except Exception as e:
            self.logger.error(f"❌ Error creando familia '{category}': {e}")
            return {}

    def create_plugin(self, plugin_name: str, **kwargs) -> Optional[BasePlugin]:
        """
        Factory method para crear un plugin específico.

        Args:
            plugin_name: Nombre del plugin
            **kwargs: Argumentos adicionales

        Returns:
            Instancia del plugin o None
        """
        try:
            # Usar el registry para crear el plugin
            plugin = self.registry.create_plugin(plugin_name, **kwargs)

            if plugin:
                # Conectar al event bus si implementa PluginInterface
                self._connect_to_event_bus(plugin)

            return plugin

        except Exception as e:
            self.logger.error(f"❌ Error creando plugin '{plugin_name}': {e}")
            return None

    # =================== PLUGIN LIFECYCLE ===================
    def activate_plugin(self, plugin_name: str, **kwargs) -> bool:
        """
        Activa un plugin específico usando Template Method pattern.

        Args:
            plugin_name: Nombre del plugin a activar
            **kwargs: Argumentos para la creación del plugin

        Returns:
            True si la activación fue exitosa
        """
        with self._lock:
            try:
                # Verificar si ya está activo
                if plugin_name in self.active_plugins:
                    self.logger.warning(f"⚠️ Plugin '{plugin_name}' ya está activo")
                    return True

                # Crear plugin
                plugin = self.create_plugin(plugin_name, **kwargs)
                if not plugin:
                    return False

                # Activar usando Template Method
                if plugin.activate():
                    self.active_plugins[plugin_name] = plugin

                    # Publicar evento de activación
                    event_bus.publish(
                        "plugin_activated",
                        {
                            "plugin_name": plugin_name,
                            "category": self.registry.get_category(plugin_name),
                        },
                        "PluginManager",
                    )

                    self.logger.info(f"✅ Plugin '{plugin_name}' activado")
                    return True
                else:
                    self.logger.error(f"❌ Falló activación de '{plugin_name}'")
                    return False

            except Exception as e:
                self.logger.error(f"❌ Error activando plugin '{plugin_name}': {e}")
                return False

    def deactivate_plugin(self, plugin_name: str) -> bool:
        """
        Desactiva un plugin específico.

        Args:
            plugin_name: Nombre del plugin a desactivar

        Returns:
            True si la desactivación fue exitosa
        """
        with self._lock:
            try:
                if plugin_name not in self.active_plugins:
                    self.logger.warning(f"⚠️ Plugin '{plugin_name}' no está activo")
                    return True

                plugin = self.active_plugins[plugin_name]

                # Desactivar usando Template Method
                if plugin.deactivate():
                    del self.active_plugins[plugin_name]

                    # Limpiar thread si existe
                    if plugin_name in self.plugin_threads:
                        del self.plugin_threads[plugin_name]

                    # Publicar evento de desactivación
                    event_bus.publish(
                        "plugin_deactivated",
                        {"plugin_name": plugin_name},
                        "PluginManager",
                    )

                    self.logger.info(f"🔴 Plugin '{plugin_name}' desactivado")
                    return True
                else:
                    self.logger.error(f"❌ Falló desactivación de '{plugin_name}'")
                    return False

            except Exception as e:
                self.logger.error(f"❌ Error desactivando plugin '{plugin_name}': {e}")
                return False

    def activate_category(self, category: str) -> bool:
        """
        Activa todos los plugins de una categoría.

        Args:
            category: Categoría a activar (detectors, interfaces, etc.)

        Returns:
            True si al menos un plugin se activó
        """
        try:
            plugin_names = self.registry.get_plugins_by_category(category)
            activated = 0

            for name in plugin_names:
                if self.activate_plugin(name):
                    activated += 1

            success = activated > 0
            self.logger.info(
                f"📂 Categoría '{category}': {activated}/{len(plugin_names)} activados"
            )
            return success

        except Exception as e:
            self.logger.error(f"❌ Error activando categoría '{category}': {e}")
            return False

    def activate_all_plugins(self) -> int:
        """
        Activa todos los plugins disponibles.

        Returns:
            Número de plugins activados exitosamente
        """
        try:
            all_plugins = self.registry.get_all_plugins()
            activated = 0

            for name in all_plugins.keys():
                if self.activate_plugin(name):
                    activated += 1

            self.logger.info(
                f"🚀 Activación masiva: {activated}/{len(all_plugins)} plugins"
            )
            return activated

        except Exception as e:
            self.logger.error(f"❌ Error en activación masiva: {e}")
            return 0

    def shutdown_all_plugins(self) -> bool:
        """
        Desactiva todos los plugins activos de manera segura.

        Returns:
            True si todos se desactivaron correctamente
        """
        try:
            active_names = list(self.active_plugins.keys())
            deactivated = 0

            for name in active_names:
                if self.deactivate_plugin(name):
                    deactivated += 1

            success = deactivated == len(active_names)
            self.logger.info(f"🛑 Shutdown: {deactivated}/{len(active_names)} plugins")
            return success

        except Exception as e:
            self.logger.error(f"❌ Error en shutdown: {e}")
            return False

    # =================== EVENT BUS INTEGRATION ===================
    def _connect_to_event_bus(self, plugin: BasePlugin):
        """
        Conecta un plugin al event bus si implementa PluginInterface.
        Implementa Observer pattern para comunicación.
        """
        try:
            # Verificar si el plugin tiene métodos de evento
            if hasattr(plugin, "on_event") and hasattr(plugin, "publish_event"):
                # Crear wrapper para conectar métodos del plugin
                def event_handler(event: Event):
                    plugin.on_event(event.event_type, event.data)

                # Suscribir a eventos relevantes según el tipo de plugin
                category = self.registry.get_category(plugin.get_name())

                if category == "interfaces":
                    # UI plugins escuchan eventos de detección
                    event_bus.subscribe(
                        "threat_detected", event_handler, plugin.get_name()
                    )
                    event_bus.subscribe(
                        "scan_complete", event_handler, plugin.get_name()
                    )
                elif category == "handlers":
                    # Handlers escuchan amenazas para tomar acción
                    event_bus.subscribe(
                        "threat_detected", event_handler, plugin.get_name()
                    )

                # Conectar método publish del plugin al event bus
                plugin.publish_event = lambda event_type, data: event_bus.publish(
                    event_type, data, plugin.get_name()
                )

                self.logger.info(
                    f"🔗 Plugin '{plugin.get_name()}' conectado al event bus"
                )

        except Exception as e:
            self.logger.error(f"❌ Error conectando plugin al event bus: {e}")

    # =================== QUERY METHODS ===================
    def get_active_plugins(self) -> List[str]:
        """Lista de nombres de plugins actualmente activos"""
        with self._lock:
            return list(self.active_plugins.keys())

    def get_plugin_status(self, plugin_name: str) -> str:
        """Estado de un plugin específico"""
        with self._lock:
            if plugin_name in self.active_plugins:
                return self.active_plugins[plugin_name].get_status()
            return "inactive"

    def get_plugin_by_name(self, plugin_name: str) -> Optional[BasePlugin]:
        """Obtiene instancia de plugin activo por nombre"""
        with self._lock:
            return self.active_plugins.get(plugin_name)

    def get_plugins_by_category(self, category: str) -> List[BasePlugin]:
        """Lista de plugins activos de una categoría"""
        with self._lock:
            return [
                plugin
                for name, plugin in self.active_plugins.items()
                if self.registry.get_category(name) == category
            ]

    def get_manager_statistics(self) -> Dict[str, Any]:
        """Estadísticas completas del plugin manager"""
        with self._lock:
            registry_stats = self.registry.get_statistics()
            event_stats = event_bus.get_statistics()

            return {
                "active_plugins": len(self.active_plugins),
                "active_by_category": {
                    category: len(self.get_plugins_by_category(category))
                    for category in ["detectors", "interfaces", "monitors", "handlers"]
                },
                "registry": registry_stats,
                "event_bus": event_stats,
                "plugin_threads": len(self.plugin_threads),
            }

    def is_plugin_active(self, plugin_name: str) -> bool:
        """Verifica si un plugin está activo"""
        with self._lock:
            return plugin_name in self.active_plugins
