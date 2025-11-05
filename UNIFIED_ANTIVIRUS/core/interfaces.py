"""
Common Interfaces - Strategy Pattern Definitions
==============================================

Define interfaces comunes que los plugins pueden implementar
para proporcionar funcionalidad específica usando Strategy Pattern.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime


class DetectorInterface(ABC):
    """
    Interface para plugins detectores usando Strategy Pattern.

    Permite intercambiar diferentes algoritmos de detección
    sin cambiar el código que los usa.
    """

    @abstractmethod
    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detecta amenazas en los datos proporcionados.

        Args:
            data: Datos del sistema para analizar

        Returns:
            Lista de amenazas detectadas con su información
        """
        pass

    @abstractmethod
    def get_confidence_score(self) -> float:
        """
        Retorna el nivel de confianza de la última detección.

        Returns:
            Score de 0.0 a 1.0 indicando confianza
        """
        pass

    @abstractmethod
    def update_signatures(self) -> bool:
        """
        Actualiza las firmas/patrones de detección.

        Returns:
            True si la actualización fue exitosa
        """
        pass

    @abstractmethod
    def get_detection_statistics(self) -> Dict[str, Any]:
        """
        Estadísticas de detección del plugin.

        Returns:
            Diccionario con estadísticas de rendimiento
        """
        pass


class MonitorInterface(ABC):
    """
    Interface para plugins monitores usando Strategy Pattern.

    Permite intercambiar diferentes estrategias de monitoreo
    del sistema sin afectar otros componentes.
    """

    @abstractmethod
    def start_monitoring(self) -> bool:
        """
        Inicia el monitoreo continuo del sistema.

        Returns:
            True si el monitoreo se inició exitosamente
        """
        pass

    @abstractmethod
    def stop_monitoring(self) -> bool:
        """
        Detiene el monitoreo del sistema.

        Returns:
            True si se detuvo exitosamente
        """
        pass

    @abstractmethod
    def get_current_data(self) -> Dict[str, Any]:
        """
        Obtiene datos actuales del sistema que está monitoreando.

        Returns:
            Diccionario con datos del sistema
        """
        pass

    @abstractmethod
    def set_data_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Establece callback para notificar nuevos datos.

        Args:
            callback: Función a llamar cuando hay nuevos datos
        """
        pass

    @abstractmethod
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """
        Estadísticas del monitoreo.

        Returns:
            Diccionario con estadísticas de monitoreo
        """
        pass


class InterfacePluginInterface(ABC):
    """
    Interface para plugins de interfaz de usuario usando Strategy Pattern.

    Permite intercambiar diferentes tipos de UI (GUI, Web, CLI)
    manteniendo la misma funcionalidad base.
    """

    @abstractmethod
    def initialize_interface(self) -> bool:
        """
        Inicializa la interfaz de usuario.

        Returns:
            True si la inicialización fue exitosa
        """
        pass

    @abstractmethod
    def show_threat_alert(self, threat_data: Dict[str, Any]) -> None:
        """
        Muestra alerta de amenaza al usuario.

        Args:
            threat_data: Información de la amenaza detectada
        """
        pass

    @abstractmethod
    def update_system_status(self, status_data: Dict[str, Any]) -> None:
        """
        Actualiza el estado del sistema en la interfaz.

        Args:
            status_data: Datos del estado actual del sistema
        """
        pass

    @abstractmethod
    def display_scan_results(self, scan_results: Dict[str, Any]) -> None:
        """
        Muestra resultados de escaneo.

        Args:
            scan_results: Resultados del escaneo realizado
        """
        pass

    @abstractmethod
    def get_user_preferences(self) -> Dict[str, Any]:
        """
        Obtiene preferencias del usuario.

        Returns:
            Diccionario con configuraciones del usuario
        """
        pass


class HandlerInterface(ABC):
    """
    Interface para plugins manejadores usando Strategy Pattern.

    Permite intercambiar diferentes estrategias de respuesta
    a amenazas (cuarentena, alerta, logging, etc.).
    """

    @abstractmethod
    def handle_threat(self, threat_data: Dict[str, Any]) -> bool:
        """
        Maneja una amenaza detectada.

        Args:
            threat_data: Información de la amenaza

        Returns:
            True si el manejo fue exitoso
        """
        pass

    @abstractmethod
    def can_handle_threat_type(self, threat_type: str) -> bool:
        """
        Verifica si puede manejar un tipo de amenaza específico.

        Args:
            threat_type: Tipo de amenaza

        Returns:
            True si puede manejar este tipo
        """
        pass

    @abstractmethod
    def get_handler_priority(self) -> int:
        """
        Prioridad del manejador (mayor número = mayor prioridad).

        Returns:
            Valor entero indicando prioridad
        """
        pass

    @abstractmethod
    def rollback_action(self, action_id: str) -> bool:
        """
        Revierte una acción previamente ejecutada.

        Args:
            action_id: Identificador de la acción a revertir

        Returns:
            True si la reversión fue exitosa
        """
        pass


class ConfigurableInterface(ABC):
    """
    Interface para plugins que soportan configuración dinámica.

    Permite actualizar configuración sin reiniciar el plugin.
    """

    @abstractmethod
    def reload_configuration(self) -> bool:
        """
        Recarga la configuración del plugin.

        Returns:
            True si la recarga fue exitosa
        """
        pass

    @abstractmethod
    def validate_configuration(self, config: Dict[str, Any]) -> List[str]:
        """
        Valida una configuración antes de aplicarla.

        Args:
            config: Configuración a validar

        Returns:
            Lista de errores de validación (vacía si es válida)
        """
        pass

    @abstractmethod
    def get_configuration_schema(self) -> Dict[str, Any]:
        """
        Esquema de configuración del plugin.

        Returns:
            Esquema JSON describiendo la configuración válida
        """
        pass


class PluginHealthInterface(ABC):
    """
    Interface para monitoreo de salud de plugins.

    Permite verificar el estado y rendimiento de los plugins.
    """

    @abstractmethod
    def perform_health_check(self) -> Dict[str, Any]:
        """
        Ejecuta verificación de salud del plugin.

        Returns:
            Diccionario con resultado del health check
        """
        pass

    @abstractmethod
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Métricas de rendimiento del plugin.

        Returns:
            Diccionario con métricas de performance
        """
        pass

    @abstractmethod
    def reset_metrics(self) -> bool:
        """
        Reinicia las métricas de rendimiento.

        Returns:
            True si el reset fue exitoso
        """
        pass


# =================== UTILITY CLASSES ===================


class ThreatInfo:
    """
    Clase de datos para información estandarizada de amenazas.
    """

    def __init__(
        self,
        threat_type: str,
        severity: str,
        description: str,
        source_plugin: str,
        confidence: float = 1.0,
        additional_data: Dict[str, Any] = None,
    ):
        self.threat_id = f"{threat_type}_{int(datetime.now().timestamp())}"
        self.threat_type = threat_type
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.description = description
        self.source_plugin = source_plugin
        self.confidence = confidence
        self.timestamp = datetime.now()
        self.additional_data = additional_data or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización"""
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "source_plugin": self.source_plugin,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "additional_data": self.additional_data,
        }


class SystemData:
    """
    Clase de datos para información estandarizada del sistema.
    """

    def __init__(self):
        self.timestamp = datetime.now()
        self.processes = []
        self.network_connections = []
        self.file_changes = []
        self.registry_changes = []
        self.system_metrics = {}

    def add_process_data(self, process_info: Dict[str, Any]):
        """Agrega información de proceso"""
        self.processes.append(process_info)

    def add_network_data(self, network_info: Dict[str, Any]):
        """Agrega información de red"""
        self.network_connections.append(network_info)

    def add_file_change(self, file_info: Dict[str, Any]):
        """Agrega cambio de archivo"""
        self.file_changes.append(file_info)

    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para análisis"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "processes": self.processes,
            "network_connections": self.network_connections,
            "file_changes": self.file_changes,
            "registry_changes": self.registry_changes,
            "system_metrics": self.system_metrics,
        }


class HandlerPluginInterface(ABC):
    """
    Interface para plugins manejadores de eventos usando Strategy Pattern.

    Permite intercambiar diferentes estrategias de manejo de eventos
    como alertas, logging, cuarentena, etc.
    """

    @abstractmethod
    def handle_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """
        Maneja un evento específico del sistema.

        Args:
            event_type: Tipo de evento (threat_detected, scan_complete, etc.)
            event_data: Datos del evento

        Returns:
            True si el evento fue manejado exitosamente
        """
        pass

    @abstractmethod
    def get_handler_status(self) -> Dict[str, Any]:
        """
        Retorna el estado actual del manejador.

        Returns:
            Diccionario con información de estado
        """
        pass


# =================== TYPE DEFINITIONS ===================

# Tipos comunes para type hints
ThreatData = Dict[str, Any]
SystemDataDict = Dict[str, Any]
ConfigDict = Dict[str, Any]
StatsDict = Dict[str, Any]
PluginCallback = Callable[[Dict[str, Any]], None]
