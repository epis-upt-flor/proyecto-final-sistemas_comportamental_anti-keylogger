"""
Alert Manager Plugin
===================

Plugin para gestionar y distribuir alertas del sistema antivirus.
Maneja diferentes tipos de notificaciones y canales de comunicación.
"""

import logging
import json
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Agregar directorio raíz al path
import sys
from pathlib import Path

current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import HandlerPluginInterface


class AlertManagerPlugin(BasePlugin, HandlerPluginInterface):
    """Gestor de alertas del sistema antivirus"""

    def __init__(self, config_path: str = None):
        super().__init__("AlertManager", "1.0.0")

        # Configuración del plugin
        self.config_path = config_path or Path(__file__).parent / "config.json"
        self.config = self._load_config()

        # Estado del gestor de alertas
        self.alert_channels = {}
        self.alert_history = []
        self.active_alerts = {}
        self.subscribers = {}

        # Threading para alertas asíncronas
        self.alert_queue = []
        self.alert_thread = None
        self.is_running = False

        # Configurar logging
        self.logger = logging.getLogger(f"plugins.handlers.{self.name.lower()}")
        self.logger.setLevel(logging.INFO)

        # Inicializar canales de alerta
        self._initialize_alert_channels()

        self.logger.info(f"[ALERT_MANAGER] Plugin inicializado")

    def _load_config(self) -> Dict[str, Any]:
        """Cargar configuración del plugin"""
        default_config = {
            "channels": {
                "console": {"enabled": True, "level": "INFO"},
                "file": {
                    "enabled": True,
                    "path": "logs/alerts.log",
                    "level": "WARNING",
                },
                "email": {"enabled": False, "smtp_server": "", "recipients": []},
                "system": {"enabled": True, "show_notifications": True},
            },
            "alert_levels": ["INFO", "WARNING", "CRITICAL", "EMERGENCY"],
            "max_history": 1000,
            "alert_timeout": 300,
        }

        try:
            if Path(self.config_path).exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # Merge con configuración por defecto
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
        except Exception as e:
            self.logger.warning(f"Error cargando configuración: {e}")

        return default_config

    def _initialize_alert_channels(self):
        """Inicializar canales de alerta"""
        # Canal de consola
        if self.config["channels"]["console"]["enabled"]:
            self.alert_channels["console"] = {
                "handler": self._send_console_alert,
                "level": self.config["channels"]["console"]["level"],
            }

        # Canal de archivo
        if self.config["channels"]["file"]["enabled"]:
            self.alert_channels["file"] = {
                "handler": self._send_file_alert,
                "level": self.config["channels"]["file"]["level"],
                "path": self.config["channels"]["file"]["path"],
            }

        # Canal de email (si está configurado)
        if self.config["channels"]["email"]["enabled"]:
            self.alert_channels["email"] = {
                "handler": self._send_email_alert,
                "level": "CRITICAL",
            }

        # Canal del sistema
        if self.config["channels"]["system"]["enabled"]:
            self.alert_channels["system"] = {
                "handler": self._send_system_alert,
                "level": "INFO",
            }

    def handle_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Manejar eventos del sistema"""
        try:
            if event_type == "threat_detected":
                return self._handle_threat_alert(event_data)
            elif event_type == "system_error":
                return self._handle_error_alert(event_data)
            elif event_type == "plugin_activated":
                return self._handle_info_alert(
                    f"Plugin activado: {event_data.get('plugin_name', 'desconocido')}"
                )
            elif event_type == "system_started":
                return self._handle_info_alert("Sistema antivirus iniciado")
            else:
                return self._handle_info_alert(f"Evento del sistema: {event_type}")
        except Exception as e:
            self.logger.error(f"Error manejando evento {event_type}: {e}")
            return False

    def handle_alert(
        self, level: str, message: str, details: Dict[str, Any] = None
    ) -> bool:
        """Método principal para enviar alertas"""
        try:
            alert = {
                "id": len(self.alert_history) + 1,
                "timestamp": datetime.now(),
                "level": level.upper(),
                "message": message,
                "details": details or {},
                "status": "active",
            }

            # Agregar a historial
            self.alert_history.append(alert)
            if len(self.alert_history) > self.config["max_history"]:
                self.alert_history.pop(0)

            # Agregar a alertas activas
            self.active_alerts[alert["id"]] = alert

            # Enviar por todos los canales apropiados
            self._distribute_alert(alert)

            self.logger.info(f"Alerta enviada: {level} - {message}")
            return True

        except Exception as e:
            self.logger.error(f"Error enviando alerta: {e}")
            return False

    def _handle_threat_alert(self, threat_data: Dict[str, Any]) -> bool:
        """Manejar alertas de amenazas"""
        threat_type = threat_data.get("threat_type", "desconocido")
        confidence = threat_data.get("confidence", 0)

        if confidence > 0.8:
            level = "CRITICAL"
        elif confidence > 0.6:
            level = "WARNING"
        else:
            level = "INFO"

        message = f"Amenaza detectada: {threat_type}"
        return self.handle_alert(level, message, threat_data)

    def _handle_error_alert(self, error_data: Dict[str, Any]) -> bool:
        """Manejar alertas de errores"""
        error_msg = error_data.get("error", "Error desconocido")
        return self.handle_alert(
            "WARNING", f"Error del sistema: {error_msg}", error_data
        )

    def _handle_info_alert(self, message: str) -> bool:
        """Manejar alertas informativas"""
        return self.handle_alert("INFO", message)

    def _distribute_alert(self, alert: Dict[str, Any]):
        """Distribuir alerta por todos los canales apropiados"""
        alert_level = alert["level"]

        for channel_name, channel_config in self.alert_channels.items():
            try:
                # Verificar si el nivel es apropiado para este canal
                if self._should_send_to_channel(alert_level, channel_config["level"]):
                    channel_config["handler"](alert)
            except Exception as e:
                self.logger.error(
                    f"Error enviando alerta por canal {channel_name}: {e}"
                )

    def _should_send_to_channel(self, alert_level: str, channel_level: str) -> bool:
        """Verificar si debe enviar alerta a un canal específico"""
        levels = {"INFO": 0, "WARNING": 1, "CRITICAL": 2, "EMERGENCY": 3}
        return levels.get(alert_level, 0) >= levels.get(channel_level, 0)

    def _send_console_alert(self, alert: Dict[str, Any]):
        """Enviar alerta a consola"""
        timestamp = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        level = alert["level"]
        message = alert["message"]

        # Colores para diferentes niveles
        colors = {
            "INFO": "\033[94m",  # Azul
            "WARNING": "\033[93m",  # Amarillo
            "CRITICAL": "\033[91m",  # Rojo
            "EMERGENCY": "\033[95m",  # Magenta
        }
        reset = "\033[0m"

        color = colors.get(level, "")
        print(f"{color}[{timestamp}] {level}: {message}{reset}")

    def _send_file_alert(self, alert: Dict[str, Any]):
        """Enviar alerta a archivo"""
        try:
            log_path = Path(self.alert_channels["file"]["path"])
            log_path.parent.mkdir(parents=True, exist_ok=True)

            timestamp = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] {alert['level']}: {alert['message']}\n"

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            self.logger.error(f"Error escribiendo alerta a archivo: {e}")

    def _send_email_alert(self, alert: Dict[str, Any]):
        """Enviar alerta por email"""
        # Implementación básica de email (requiere configuración SMTP)
        self.logger.info(f"Email alert: {alert['message']}")

    def _send_system_alert(self, alert: Dict[str, Any]):
        """Enviar notificación del sistema"""
        try:
            import platform

            if platform.system() == "Windows":
                # Windows notification
                import os

                os.system(f'msg * "Antivirus Alert: {alert["message"]}"')
            else:
                # Linux notification (notify-send)
                import subprocess

                subprocess.run(["notify-send", "Antivirus Alert", alert["message"]])
        except Exception as e:
            self.logger.debug(f"No se pudo enviar notificación del sistema: {e}")

    def get_handler_status(self) -> Dict[str, Any]:
        """Obtener estado del gestor de alertas"""
        return {
            "active": True,
            "channels_active": len(self.alert_channels),
            "channels": list(self.alert_channels.keys()),
            "total_alerts": len(self.alert_history),
            "active_alerts": len(self.active_alerts),
            "last_alert": (
                self.alert_history[-1]["timestamp"] if self.alert_history else None
            ),
        }

    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obtener historial de alertas"""
        return self.alert_history[-limit:] if limit else self.alert_history

    def get_active_alerts(self) -> Dict[int, Dict[str, Any]]:
        """Obtener alertas activas"""
        return self.active_alerts

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Marcar alerta como reconocida"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id]["status"] = "acknowledged"
            return True
        return False

    def clear_alert(self, alert_id: int) -> bool:
        """Limpiar/cerrar alerta"""
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
            return True
        return False

    def subscribe_to_alerts(self, subscriber_id: str, callback: Callable) -> bool:
        """Suscribirse a alertas"""
        self.subscribers[subscriber_id] = callback
        return True

    def unsubscribe_from_alerts(self, subscriber_id: str) -> bool:
        """Desuscribirse de alertas"""
        if subscriber_id in self.subscribers:
            del self.subscribers[subscriber_id]
            return True
        return False


def create_plugin(config_path: str = None) -> AlertManagerPlugin:
    """Función factory para crear el plugin"""
    return AlertManagerPlugin(config_path)


if __name__ == "__main__":
    # Test básico del plugin
    alert_manager = AlertManagerPlugin()

    # Probar diferentes tipos de alertas
    alert_manager.handle_alert("INFO", "Sistema iniciado correctamente")
    alert_manager.handle_alert("WARNING", "Uso elevado de CPU detectado")
    alert_manager.handle_alert(
        "CRITICAL",
        "Posible keylogger detectado",
        {"process": "suspicious.exe", "confidence": 0.85},
    )

    print(f"Estado: {alert_manager.get_handler_status()}")
    print(f"Historial: {len(alert_manager.get_alert_history())} alertas")
