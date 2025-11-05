"""
Logger Utility - Advanced logging system for the Unified Antivirus
=================================================================

Sistema de logging avanzado con múltiples niveles, rotación de archivos
y formateo especializado para el sistema antivirus.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
import threading


class Logger:
    """
    Utilidad de logging avanzada con múltiples características:
    - Rotación automática de archivos
    - Múltiples formatos de salida
    - Logging estructurado (JSON)
    - Thread-safe
    - Configuración dinámica
    """

    _instances: Dict[str, "Logger"] = {}
    _lock = threading.Lock()

    def __init__(self, name: str, log_dir: str = "logs", level: str = "INFO"):
        """
        Inicializa el logger

        Args:
            name: Nombre del logger
            log_dir: Directorio de logs
            level: Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.level = getattr(logging, level.upper())

        # Crear directorio de logs si no existe
        self.log_dir.mkdir(exist_ok=True)

        # Configurar logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.level)

        # Evitar duplicar handlers
        if not self.logger.handlers:
            self._setup_handlers()

        self.logger.info(f"📝 Logger '{name}' inicializado")

    @classmethod
    def get_logger(
        cls, name: str, log_dir: str = "logs", level: str = "INFO"
    ) -> "Logger":
        """
        Singleton pattern para obtener logger por nombre

        Args:
            name: Nombre del logger
            log_dir: Directorio de logs
            level: Nivel de logging

        Returns:
            Instancia del logger
        """
        with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = cls(name, log_dir, level)
            return cls._instances[name]

    def _setup_handlers(self):
        """Configura handlers de logging"""

        # Handler para archivo general (con rotación)
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"{self.name}.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)

        # Handler para errores (archivo separado)
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"{self.name}_errors.log",
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)

        # Handler para consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # Handler para logs estructurados (JSON)
        json_handler = logging.FileHandler(
            self.log_dir / f"{self.name}_structured.jsonl", encoding="utf-8"
        )
        json_handler.setLevel(logging.INFO)

        # Formatters
        detailed_formatter = logging.Formatter(
            "[%(asctime)s] %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S"
        )

        json_formatter = JsonFormatter()

        # Asignar formatters
        file_handler.setFormatter(detailed_formatter)
        error_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(console_formatter)
        json_handler.setFormatter(json_formatter)

        # Agregar handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(json_handler)

    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log mensaje de debug"""
        self.logger.debug(message, extra=extra or {})

    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log mensaje informativo"""
        self.logger.info(message, extra=extra or {})

    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log mensaje de advertencia"""
        self.logger.warning(message, extra=extra or {})

    def error(self, message: str, extra: Dict[str, Any] = None, exc_info: bool = False):
        """Log mensaje de error"""
        self.logger.error(message, extra=extra or {}, exc_info=exc_info)

    def critical(
        self, message: str, extra: Dict[str, Any] = None, exc_info: bool = False
    ):
        """Log mensaje crítico"""
        self.logger.critical(message, extra=extra or {}, exc_info=exc_info)

    def log_event(self, event_type: str, data: Dict[str, Any], level: str = "INFO"):
        """
        Log de evento estructurado

        Args:
            event_type: Tipo de evento
            data: Datos del evento
            level: Nivel de logging
        """
        event_data = {
            "event_type": event_type,
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }

        level_method = getattr(self, level.lower())
        level_method(f"EVENT: {event_type}", extra=event_data)

    def log_threat(self, threat_type: str, confidence: float, details: Dict[str, Any]):
        """
        Log específico para amenazas detectadas

        Args:
            threat_type: Tipo de amenaza
            confidence: Nivel de confianza
            details: Detalles de la amenaza
        """
        threat_data = {
            "threat_type": threat_type,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
            "details": details,
        }

        self.warning(
            f"🚨 THREAT DETECTED: {threat_type} (confidence: {confidence:.2f})",
            extra=threat_data,
        )

    def log_performance(
        self, operation: str, duration: float, details: Dict[str, Any] = None
    ):
        """
        Log específico para métricas de rendimiento

        Args:
            operation: Nombre de la operación
            duration: Duración en segundos
            details: Detalles adicionales
        """
        perf_data = {
            "operation": operation,
            "duration_seconds": duration,
            "timestamp": datetime.now().isoformat(),
            "details": details or {},
        }

        self.info(f"⏱️ PERFORMANCE: {operation} took {duration:.3f}s", extra=perf_data)

    def set_level(self, level: str):
        """Cambia el nivel de logging dinámicamente"""
        new_level = getattr(logging, level.upper())
        self.logger.setLevel(new_level)
        self.level = new_level
        self.info(f"📝 Log level changed to {level}")

    def get_log_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de logging"""
        log_files = list(self.log_dir.glob(f"{self.name}*.log*"))

        stats = {
            "logger_name": self.name,
            "current_level": logging.getLevelName(self.level),
            "log_directory": str(self.log_dir),
            "log_files": len(log_files),
            "total_log_size_mb": sum(f.stat().st_size for f in log_files)
            / (1024 * 1024),
            "handlers_count": len(self.logger.handlers),
        }

        return stats


class JsonFormatter(logging.Formatter):
    """Formatter personalizado para logs estructurados en JSON"""

    def format(self, record):
        """Formatea el record como JSON estructurado"""

        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Agregar datos extra si existen
        if hasattr(record, "extra"):
            log_entry.update(record.extra)

        # Agregar información de excepción si existe
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


# =================== CONVENIENCE FUNCTIONS ===================
def get_logger(name: str, log_dir: str = "logs", level: str = "INFO") -> Logger:
    """Función de conveniencia para obtener un logger"""
    return Logger.get_logger(name, log_dir, level)


def setup_root_logger(log_dir: str = "logs", level: str = "INFO"):
    """Configura el logger root del sistema"""
    return Logger.get_logger("antivirus_system", log_dir, level)


def log_system_startup(components: list, logger_name: str = "system"):
    """Log específico para inicio del sistema"""
    logger = get_logger(logger_name)
    logger.log_event(
        "system_startup",
        {"components": components, "startup_time": datetime.now().isoformat()},
    )


def log_plugin_activity(plugin_name: str, action: str, details: Dict[str, Any] = None):
    """Log específico para actividad de plugins"""
    logger = get_logger("plugins")
    logger.log_event(
        "plugin_activity",
        {"plugin_name": plugin_name, "action": action, "details": details or {}},
    )
