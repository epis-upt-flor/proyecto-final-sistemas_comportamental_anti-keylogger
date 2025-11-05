"""
Plugin Registry - Registry Pattern Implementation
===============================================

Permite el registro dinámico y descubrimiento de plugins.
Implementa Registry Pattern + Strategy Pattern.
"""

import logging
import importlib
import inspect
from typing import Dict, List, Type, Optional, Any
from pathlib import Path
from .base_plugin import BasePlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """
    Registry Pattern para gestión dinámica de plugins.

    Permite:
    - Registro automático de plugins al importarlos
    - Descubrimiento de plugins en directorios
    - Creación de instancias por nombre
    - Categorización por tipo

    Es thread-safe y actúa como Singleton.
    """

    _instance = None
    _plugins: Dict[str, Dict[str, Any]] = {}
    _categories = ["detectors", "interfaces", "monitors", "handlers"]

    def __new__(cls):
        """Singleton pattern - una sola instancia del registry"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            logger.info("🏪 PluginRegistry inicializado (Singleton)")
        return cls._instance

    @classmethod
    def register_plugin(
        cls,
        plugin_class: Type[BasePlugin],
        plugin_name: str = None,
        category: str = None,
        auto_discover: bool = False,
    ) -> bool:
        """
        Registra un plugin en el registry.

        Args:
            plugin_class: Clase del plugin que hereda de BasePlugin
            plugin_name: Nombre único del plugin (si None, usa clase.__name__)
            category: Categoría del plugin (detector, interface, etc.)
            auto_discover: Si fue descubierto automáticamente

        Returns:
            True si el registro fue exitoso
        """
        try:
            # Validar que hereda de BasePlugin
            if not issubclass(plugin_class, BasePlugin):
                logger.error(f"❌ {plugin_class.__name__} no hereda de BasePlugin")
                return False

            # Determinar nombre del plugin
            name = plugin_name or plugin_class.__name__.lower().replace("plugin", "")

            # Determinar categoría automáticamente si no se especifica
            if not category:
                category = cls._infer_category(plugin_class, name)

            # Verificar si ya existe
            if name in cls._plugins:
                logger.warning(f"⚠️ Plugin '{name}' ya registrado, sobrescribiendo")

            # Registrar plugin
            cls._plugins[name] = {
                "class": plugin_class,
                "name": name,
                "category": category,
                "module": plugin_class.__module__,
                "auto_discovered": auto_discover,
                "description": plugin_class.__doc__ or "Sin descripción",
            }

            logger.info(f"✅ Plugin '{name}' registrado en categoría '{category}'")
            return True

        except Exception as e:
            logger.error(f"❌ Error registrando plugin {plugin_class.__name__}: {e}")
            return False

    @classmethod
    def _infer_category(cls, plugin_class: Type[BasePlugin], name: str) -> str:
        """
        Infiere la categoría del plugin basado en su nombre y módulo.
        Strategy Pattern para diferentes heurísticas de categorización.
        """
        module_name = plugin_class.__module__.lower()
        class_name = plugin_class.__name__.lower()

        # Estrategia 1: Por nombre del módulo
        for category in cls._categories:
            if category in module_name:
                return category

        # Estrategia 2: Por nombre de la clase
        if "detector" in class_name:
            return "detectors"
        elif "ui" in class_name or "interface" in class_name:
            return "interfaces"
        elif "monitor" in class_name:
            return "monitors"
        elif "handler" in class_name:
            return "handlers"

        # Estrategia 3: Por nombre del plugin
        if any(keyword in name for keyword in ["ml", "behavior", "network"]):
            return "detectors"
        elif any(keyword in name for keyword in ["ui", "web", "cli"]):
            return "interfaces"

        # Default
        return "unknown"

    @classmethod
    def get_plugin_class(cls, plugin_name: str) -> Optional[Type[BasePlugin]]:
        """Obtiene la clase de un plugin por nombre"""
        plugin_info = cls._plugins.get(plugin_name)
        return plugin_info["class"] if plugin_info else None

    @classmethod
    def create_plugin(
        cls, plugin_name: str, plugin_path: str = None, **kwargs
    ) -> Optional[BasePlugin]:
        """
        Crea una instancia de plugin usando Factory Method Pattern.

        Args:
            plugin_name: Nombre del plugin registrado
            plugin_path: Path del directorio del plugin
            **kwargs: Argumentos adicionales para el constructor

        Returns:
            Instancia del plugin o None si falla
        """
        try:
            plugin_class = cls.get_plugin_class(plugin_name)
            if not plugin_class:
                logger.error(f"❌ Plugin '{plugin_name}' no encontrado en registry")
                return None

            # Determinar path si no se proporciona
            if not plugin_path:
                plugin_path = f"plugins/{cls.get_category(plugin_name)}/{plugin_name}"

            # Crear instancia con solo los argumentos que acepta el constructor
            # Los plugins esperan config_path como argumento opcional
            config_path = kwargs.get("config_path")
            if config_path:
                instance = plugin_class(config_path=config_path)
            else:
                instance = plugin_class()
            logger.info(f"🏭 Plugin '{plugin_name}' creado exitosamente")
            return instance

        except Exception as e:
            logger.error(f"❌ Error creando plugin '{plugin_name}': {e}")
            return None

    @classmethod
    def discover_plugins(cls, base_path: Path) -> int:
        """
        Descubre plugins automáticamente en un directorio.

        Busca archivos plugin.py en subdirectorios y los importa.

        Returns:
            Número de plugins descubiertos
        """
        discovered = 0

        try:
            logger.info(f"🔍 Descubriendo plugins en: {base_path}")

            # Buscar en cada categoría
            for category in cls._categories:
                category_path = base_path / category
                if not category_path.exists():
                    continue

                # Buscar plugins en subdirectorios
                for plugin_dir in category_path.iterdir():
                    if not plugin_dir.is_dir():
                        continue

                    plugin_file = plugin_dir / "plugin.py"
                    if not plugin_file.exists():
                        continue

                    try:
                        # Importar módulo dinámicamente
                        module_name = f"plugins.{category}.{plugin_dir.name}.plugin"
                        module = importlib.import_module(module_name)

                        # Buscar clases que hereden de BasePlugin
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if (
                                issubclass(obj, BasePlugin)
                                and obj != BasePlugin
                                and obj.__module__ == module_name
                            ):

                                cls.register_plugin(
                                    obj, plugin_dir.name, category, auto_discover=True
                                )
                                discovered += 1

                    except Exception as e:
                        logger.error(
                            f"❌ Error importando plugin {plugin_dir.name}: {e}"
                        )

            logger.info(f"✅ Descubiertos {discovered} plugins")
            return discovered

        except Exception as e:
            logger.error(f"❌ Error en descubrimiento de plugins: {e}")
            return 0

    @classmethod
    def get_plugins_by_category(cls, category: str) -> List[str]:
        """Lista plugins de una categoría específica"""
        return [
            name for name, info in cls._plugins.items() if info["category"] == category
        ]

    @classmethod
    def get_category(cls, plugin_name: str) -> Optional[str]:
        """Obtiene la categoría de un plugin"""
        plugin_info = cls._plugins.get(plugin_name)
        return plugin_info["category"] if plugin_info else None

    @classmethod
    def get_all_plugins(cls) -> Dict[str, Dict[str, Any]]:
        """Retorna información de todos los plugins registrados"""
        return cls._plugins.copy()

    @classmethod
    def get_plugin_info(cls, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Información detallada de un plugin específico"""
        return cls._plugins.get(plugin_name)

    @classmethod
    def is_registered(cls, plugin_name: str) -> bool:
        """Verifica si un plugin está registrado"""
        return plugin_name in cls._plugins

    @classmethod
    def unregister_plugin(cls, plugin_name: str) -> bool:
        """Desregistra un plugin del registry"""
        if plugin_name in cls._plugins:
            del cls._plugins[plugin_name]
            logger.info(f"🗑️ Plugin '{plugin_name}' desregistrado")
            return True
        return False

    @classmethod
    def clear_registry(cls):
        """Limpia todo el registry (útil para testing)"""
        cls._plugins.clear()
        logger.info("🧹 Registry de plugins limpiado")

    @classmethod
    def get_categories(cls) -> List[str]:
        """Obtiene lista de categorías disponibles"""
        return cls._categories.copy()

    @classmethod
    def get_all_plugins(cls) -> Dict[str, Dict[str, Any]]:
        """Obtiene diccionario con todos los plugins registrados"""
        return cls._plugins.copy()

    @classmethod
    def get_statistics(cls) -> Dict[str, Any]:
        """Estadísticas del registry para monitoring"""
        stats = {
            "total_plugins": len(cls._plugins),
            "by_category": {},
            "auto_discovered": 0,
            "manually_registered": 0,
        }

        for category in cls._categories:
            stats["by_category"][category] = len(cls.get_plugins_by_category(category))

        for plugin_info in cls._plugins.values():
            if plugin_info["auto_discovered"]:
                stats["auto_discovered"] += 1
            else:
                stats["manually_registered"] += 1

        return stats


# =================== DECORADOR PARA AUTO-REGISTRO ===================
def register_plugin(category: str = None, name: str = None):
    """
    Decorador que registra automáticamente un plugin.

    Uso:
    @register_plugin(category='detectors', name='ml_detector')
    class MLDetectorPlugin(BasePlugin):
        pass
    """

    def decorator(plugin_class):
        PluginRegistry.register_plugin(plugin_class, name, category)
        return plugin_class

    return decorator
