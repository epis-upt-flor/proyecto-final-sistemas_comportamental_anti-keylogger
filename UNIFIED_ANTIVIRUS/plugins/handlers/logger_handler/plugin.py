"""
Logger Handler Plugin
====================

Plugin especializado en el manejo avanzado de logs del sistema antivirus.
Proporciona logging estructurado, rotación de logs y análisis de patrones.
"""

import logging
import json
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import gzip
import shutil
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Agregar directorio raíz al path
import sys
from pathlib import Path
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import HandlerPluginInterface


class LoggerHandlerPlugin(BasePlugin, HandlerPluginInterface):
    """Handler avanzado de logging para el sistema antivirus"""
    
    def __init__(self, config_path: str = None):
        super().__init__("LoggerHandler", "1.0.0")
        
        # Configuración del plugin
        self.config_path = config_path or Path(__file__).parent / "config.json"
        self.config = self._load_config()
        
        # Estado del logger
        self.loggers = {}
        self.log_stats = {
            "total_logs": 0,
            "logs_by_level": {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
            "logs_by_component": {},
            "session_start": datetime.now()
        }
        
        # Buffer para logs de alta frecuencia
        self.log_buffer = []
        self.buffer_lock = threading.Lock()
        self.flush_thread = None
        
        # Configurar logging principal
        self.logger = logging.getLogger(f"plugins.handlers.{self.name.lower()}")
        self.logger.setLevel(logging.INFO)
        
        # Inicializar loggers especializados
        self._initialize_loggers()
        
        # Iniciar thread de flush si está configurado
        if self.config.get("buffer_enabled", False):
            self._start_flush_thread()
        
        self.logger.info(f"[LOGGER_HANDLER] Plugin inicializado con {len(self.loggers)} loggers")
    
    def _load_config(self) -> Dict[str, Any]:
        """Cargar configuración del plugin"""
        default_config = {
            "loggers": {
                "main": {
                    "file": "logs/antivirus.log",
                    "level": "INFO",
                    "max_size": "10MB",
                    "backup_count": 5,
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                },
                "threats": {
                    "file": "logs/threats.log",
                    "level": "WARNING",
                    "max_size": "50MB",
                    "backup_count": 10,
                    "format": "%(asctime)s - THREAT - %(levelname)s - %(message)s"
                },
                "performance": {
                    "file": "logs/performance.log",
                    "level": "INFO",
                    "max_size": "20MB",
                    "backup_count": 3,
                    "format": "%(asctime)s - PERF - %(message)s"
                },
                "audit": {
                    "file": "logs/audit.log",
                    "level": "INFO",
                    "max_size": "100MB",
                    "backup_count": 20,
                    "format": "%(asctime)s - AUDIT - %(message)s"
                }
            },
            "buffer_enabled": True,
            "buffer_size": 100,
            "flush_interval": 5,
            "compress_old_logs": True,
            "json_logging": True,
            "log_retention_days": 30
        }
        
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Merge con configuración por defecto
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
        except Exception as e:
            self.logger.warning(f"Error cargando configuración: {e}")
        
        return default_config
    
    def _initialize_loggers(self):
        """Inicializar loggers especializados"""
        for logger_name, logger_config in self.config["loggers"].items():
            try:
                # Crear logger
                logger = logging.getLogger(f"antivirus.{logger_name}")
                logger.setLevel(getattr(logging, logger_config["level"]))
                
                # Crear directorio si no existe
                log_file = Path(logger_config["file"])
                log_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Configurar handler con rotación
                max_size = self._parse_size(logger_config["max_size"])
                handler = RotatingFileHandler(
                    log_file,
                    maxBytes=max_size,
                    backupCount=logger_config["backup_count"],
                    encoding='utf-8'
                )
                
                # Configurar formato
                formatter = logging.Formatter(logger_config["format"])
                handler.setFormatter(formatter)
                
                # Agregar handler al logger
                logger.addHandler(handler)
                
                # Almacenar referencia
                self.loggers[logger_name] = {
                    "logger": logger,
                    "handler": handler,
                    "config": logger_config,
                    "stats": {"messages": 0, "last_log": None}
                }
                
            except Exception as e:
                self.logger.error(f"Error inicializando logger {logger_name}: {e}")
    
    def _parse_size(self, size_str: str) -> int:
        """Convertir string de tamaño a bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def handle_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Manejar eventos del sistema"""
        try:
            if event_type == "threat_detected":
                return self._log_threat_event(event_data)
            elif event_type == "system_error":
                return self._log_error_event(event_data)
            elif event_type == "performance_metric":
                return self._log_performance_event(event_data)
            elif event_type == "user_action":
                return self._log_audit_event(event_data)
            else:
                return self._log_general_event(event_type, event_data)
        except Exception as e:
            self.logger.error(f"Error manejando evento {event_type}: {e}")
            return False
    
    def log_event(self, logger_name: str, level: str, message: str, extra_data: Dict[str, Any] = None) -> bool:
        """Método principal para logging"""
        try:
            if logger_name not in self.loggers:
                logger_name = "main"  # Fallback al logger principal
            
            logger_info = self.loggers[logger_name]
            logger = logger_info["logger"]
            
            # Preparar mensaje
            if self.config.get("json_logging", False) and extra_data:
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "level": level,
                    "message": message,
                    "data": extra_data
                }
                formatted_message = json.dumps(log_entry, ensure_ascii=False)
            else:
                formatted_message = message
            
            # Enviar log
            log_level = getattr(logging, level.upper(), logging.INFO)
            logger.log(log_level, formatted_message)
            
            # Actualizar estadísticas
            self._update_stats(logger_name, level, message)
            
            # Agregar al buffer si está habilitado
            if self.config.get("buffer_enabled", False):
                self._add_to_buffer(logger_name, level, message, extra_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error en log_event: {e}")
            return False
    
    def _log_threat_event(self, threat_data: Dict[str, Any]) -> bool:
        """Logging de eventos de amenazas"""
        threat_type = threat_data.get("threat_type", "unknown")
        confidence = threat_data.get("confidence", 0)
        
        message = f"Threat detected: {threat_type} (confidence: {confidence:.2f})"
        return self.log_event("threats", "WARNING", message, threat_data)
    
    def _log_error_event(self, error_data: Dict[str, Any]) -> bool:
        """Logging de eventos de error"""
        error_msg = error_data.get("error", "Unknown error")
        component = error_data.get("component", "system")
        
        message = f"Error in {component}: {error_msg}"
        return self.log_event("main", "ERROR", message, error_data)
    
    def _log_performance_event(self, perf_data: Dict[str, Any]) -> bool:
        """Logging de métricas de rendimiento"""
        metric_name = perf_data.get("metric", "unknown")
        value = perf_data.get("value", 0)
        
        message = f"{metric_name}: {value}"
        return self.log_event("performance", "INFO", message, perf_data)
    
    def _log_audit_event(self, audit_data: Dict[str, Any]) -> bool:
        """Logging de eventos de auditoría"""
        action = audit_data.get("action", "unknown")
        user = audit_data.get("user", "system")
        
        message = f"User {user} performed: {action}"
        return self.log_event("audit", "INFO", message, audit_data)
    
    def _log_general_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Logging de eventos generales"""
        message = f"System event: {event_type}"
        return self.log_event("main", "INFO", message, event_data)
    
    def _update_stats(self, logger_name: str, level: str, message: str):
        """Actualizar estadísticas de logging"""
        with self.buffer_lock:
            self.log_stats["total_logs"] += 1
            
            if level.upper() in self.log_stats["logs_by_level"]:
                self.log_stats["logs_by_level"][level.upper()] += 1
            
            if logger_name not in self.log_stats["logs_by_component"]:
                self.log_stats["logs_by_component"][logger_name] = 0
            self.log_stats["logs_by_component"][logger_name] += 1
            
            # Actualizar stats del logger específico
            if logger_name in self.loggers:
                self.loggers[logger_name]["stats"]["messages"] += 1
                self.loggers[logger_name]["stats"]["last_log"] = datetime.now()
    
    def _add_to_buffer(self, logger_name: str, level: str, message: str, extra_data: Dict[str, Any]):
        """Agregar entrada al buffer"""
        with self.buffer_lock:
            self.log_buffer.append({
                "timestamp": datetime.now(),
                "logger": logger_name,
                "level": level,
                "message": message,
                "data": extra_data
            })
            
            # Flush si el buffer está lleno
            if len(self.log_buffer) >= self.config.get("buffer_size", 100):
                self._flush_buffer()
    
    def _start_flush_thread(self):
        """Iniciar thread para flush periódico del buffer"""
        def flush_worker():
            while True:
                threading.Event().wait(self.config.get("flush_interval", 5))
                if self.log_buffer:
                    self._flush_buffer()
        
        self.flush_thread = threading.Thread(target=flush_worker, daemon=True)
        self.flush_thread.start()
    
    def _flush_buffer(self):
        """Flush del buffer a archivos"""
        with self.buffer_lock:
            if not self.log_buffer:
                return
            
            # Procesar entradas del buffer
            for entry in self.log_buffer:
                try:
                    # Escribir a archivo correspondiente
                    logger_name = entry["logger"]
                    if logger_name in self.loggers:
                        logger = self.loggers[logger_name]["logger"]
                        log_level = getattr(logging, entry["level"].upper(), logging.INFO)
                        logger.log(log_level, f"BUFFERED: {entry['message']}")
                except Exception as e:
                    self.logger.error(f"Error flushing buffer entry: {e}")
            
            # Limpiar buffer
            self.log_buffer.clear()
    
    def get_handler_status(self) -> Dict[str, Any]:
        """Obtener estado del handler"""
        return {
            "active": True,
            "loggers_count": len(self.loggers),
            "loggers": list(self.loggers.keys()),
            "total_logs": self.log_stats["total_logs"],
            "buffer_size": len(self.log_buffer),
            "session_duration": str(datetime.now() - self.log_stats["session_start"]),
            "logs_by_level": self.log_stats["logs_by_level"],
            "logs_by_component": self.log_stats["logs_by_component"]
        }
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas detalladas de logging"""
        return self.log_stats.copy()
    
    def get_recent_logs(self, logger_name: str, count: int = 100) -> List[str]:
        """Obtener logs recientes de un logger específico"""
        try:
            if logger_name not in self.loggers:
                return []
            
            log_file = Path(self.loggers[logger_name]["config"]["file"])
            if not log_file.exists():
                return []
            
            # Leer últimas líneas del archivo
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                return lines[-count:] if len(lines) > count else lines
                
        except Exception as e:
            self.logger.error(f"Error leyendo logs recientes: {e}")
            return []
    
    def rotate_logs(self, logger_name: str = None) -> bool:
        """Forzar rotación de logs"""
        try:
            if logger_name:
                if logger_name in self.loggers:
                    handler = self.loggers[logger_name]["handler"]
                    if isinstance(handler, RotatingFileHandler):
                        handler.doRollover()
                        return True
            else:
                # Rotar todos los logs
                for name, logger_info in self.loggers.items():
                    handler = logger_info["handler"]
                    if isinstance(handler, RotatingFileHandler):
                        handler.doRollover()
                return True
                
        except Exception as e:
            self.logger.error(f"Error en rotación de logs: {e}")
            return False
    
    def cleanup_old_logs(self, days: int = None) -> int:
        """Limpiar logs antiguos"""
        days = days or self.config.get("log_retention_days", 30)
        cutoff_date = datetime.now() - timedelta(days=days)
        cleaned = 0
        
        try:
            logs_dir = Path("logs")
            if logs_dir.exists():
                for log_file in logs_dir.glob("*.log*"):
                    if log_file.stat().st_mtime < cutoff_date.timestamp():
                        log_file.unlink()
                        cleaned += 1
                        
        except Exception as e:
            self.logger.error(f"Error limpiando logs antiguos: {e}")
        
        return cleaned


def create_plugin(config_path: str = None) -> LoggerHandlerPlugin:
    """Función factory para crear el plugin"""
    return LoggerHandlerPlugin(config_path)


if __name__ == "__main__":
    # Test básico del plugin
    logger_handler = LoggerHandlerPlugin()
    
    # Probar diferentes tipos de logs
    logger_handler.log_event("main", "INFO", "Sistema iniciado")
    logger_handler.log_event("threats", "WARNING", "Posible amenaza detectada")
    logger_handler.log_event("performance", "INFO", "CPU: 45%")
    logger_handler.log_event("audit", "INFO", "Usuario realizó escaneo")
    
    print(f"Estado: {logger_handler.get_handler_status()}")
    print(f"Stats: {logger_handler.get_log_stats()}")