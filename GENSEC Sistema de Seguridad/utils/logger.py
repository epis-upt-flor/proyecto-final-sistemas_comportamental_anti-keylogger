"""
Logger Utility - Advanced logging system for the Unified Antivirus
=================================================================

Sistema de logging avanzado con múltiples niveles, rotación de archivos
y formateo especializado para el sistema antivirus.
Incluye integración con servidor web de monitoreo.
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

# Importar log sender (será None si no está disponible)
try:
    from .log_sender import get_log_sender, init_log_sender
    LOG_SENDER_AVAILABLE = True
except ImportError:
    LOG_SENDER_AVAILABLE = False
    get_log_sender = lambda: None
    init_log_sender = lambda *args, **kwargs: None

# Importar nuevo sistema de web logging
try:
    import sys
    from pathlib import Path
    
    # Agregar el directorio raíz del proyecto al path si no está
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    from web_system.integration import (
        WebLogHandler, 
        WebLogConfigManager,
        setup_antivirus_web_logging,
        get_web_logging_status
    )
    WEB_LOGGING_AVAILABLE = True
except ImportError as e:
    WEB_LOGGING_AVAILABLE = False
    WebLogHandler = None
    WebLogConfigManager = None
    setup_antivirus_web_logging = lambda *args, **kwargs: {'success': False, 'errors': ['Web logging no disponible']}
    get_web_logging_status = lambda: {'enabled': False, 'reason': 'not_available'}


class Logger:
    """
    Utilidad de logging avanzada con múltiples características:
    - Rotación automática de archivos
    - Múltiples formatos de salida
    - Logging estructurado (JSON)
    - Thread-safe
    - Configuración dinámica
    """
    
    _instances: Dict[str, 'Logger'] = {}
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
        
        # Configurar web logging si está disponible y habilitado
        self._setup_web_logging()
    
    def _setup_web_logging(self):
        """Configura web logging automáticamente si está disponible"""
        if not WEB_LOGGING_AVAILABLE:
            return
        
        try:
            # Verificar configuración
            manager = WebLogConfigManager()
            config = manager.get_config()
            
            if config.enabled and manager.validate_config():
                # Verificar si ya tiene WebLogHandler
                has_web_handler = any(
                    isinstance(h, WebLogHandler) for h in self.logger.handlers
                )
                
                if not has_web_handler:
                    # Crear y agregar WebLogHandler
                    from web_system.integration import setup_web_logging_from_config
                    handler = setup_web_logging_from_config()
                    
                    if handler:
                        self.logger.addHandler(handler)
                        self.logger.debug(f"🌐 Web logging habilitado para '{self.name}'")
                    
        except Exception as e:
            self.logger.debug(f"⚠️ No se pudo configurar web logging: {e}")
    
    @classmethod
    def get_logger(cls, name: str, log_dir: str = "logs", level: str = "INFO") -> 'Logger':
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
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # Handler para errores (archivo separado)
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"{self.name}_errors.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        
        # Handler para consola
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Handler para logs estructurados (JSON)
        json_handler = logging.FileHandler(
            self.log_dir / f"{self.name}_structured.jsonl",
            encoding='utf-8'
        )
        json_handler.setLevel(logging.INFO)
        
        # Formatters
        detailed_formatter = logging.Formatter(
            '[%(asctime)s] %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
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
    
    def critical(self, message: str, extra: Dict[str, Any] = None, exc_info: bool = False):
        """Log mensaje crítico"""
        self.logger.critical(message, extra=extra or {}, exc_info=exc_info)
        
        # Enviar logs críticos inmediatamente al servidor si está disponible
        if LOG_SENDER_AVAILABLE:
            sender = get_log_sender()
            if sender:
                try:
                    sender.send_manual_log("CRITICAL", message, self.name)
                except Exception:
                    pass  # No fallar si el envío falla
    
    def log_event(self, event_type: str, data: Dict[str, Any], level: str = "INFO"):
        """
        Log de evento estructurado
        
        Args:
            event_type: Tipo de evento
            data: Datos del evento
            level: Nivel de logging
        """
        event_data = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
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
            'threat_type': threat_type,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        
        self.warning(f"🚨 THREAT DETECTED: {threat_type} (confidence: {confidence:.2f})", 
                    extra=threat_data)
    
    def log_performance(self, operation: str, duration: float, details: Dict[str, Any] = None):
        """
        Log específico para métricas de rendimiento
        
        Args:
            operation: Nombre de la operación
            duration: Duración en segundos
            details: Detalles adicionales
        """
        perf_data = {
            'operation': operation,
            'duration_seconds': duration,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
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
            'logger_name': self.name,
            'current_level': logging.getLevelName(self.level),
            'log_directory': str(self.log_dir),
            'log_files': len(log_files),
            'total_log_size_mb': sum(f.stat().st_size for f in log_files) / (1024*1024),
            'handlers_count': len(self.logger.handlers)
        }
        
        return stats


class JsonFormatter(logging.Formatter):
    """Formatter personalizado para logs estructurados en JSON"""
    
    def format(self, record):
        """Formatea el record como JSON estructurado"""
        
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Agregar datos extra si existen
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
        
        # Agregar información de excepción si existe
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False)


# =================== WEB MONITORING INTEGRATION ===================
def setup_web_monitoring(server_url: str, **kwargs):
    """
    Configura el envío de logs al servidor web de monitoreo
    
    Args:
        server_url: URL del servidor web (ej: http://servidor:8000)
        **kwargs: Parámetros adicionales para LogSender
    """
    if not LOG_SENDER_AVAILABLE:
        print("⚠️ Log sender no disponible. Instalar dependencias de monitoreo web.")
        return None
    
    try:
        sender = init_log_sender(server_url, **kwargs)
        sender.start()
        
        # Log inicial
        sender.send_manual_log("INFO", "Sistema de monitoreo web iniciado", "web_monitor")
        
        print(f"✅ Monitoreo web configurado: {server_url}")
        return sender
    except Exception as e:
        print(f"❌ Error configurando monitoreo web: {e}")
        return None

def get_web_monitoring_status() -> Dict[str, Any]:
    """Obtiene el estado del sistema de monitoreo web"""
    if not LOG_SENDER_AVAILABLE:
        return {"enabled": False, "reason": "log_sender_not_available"}
    
    sender = get_log_sender()
    if not sender:
        return {"enabled": False, "reason": "not_initialized"}
    
    return {"enabled": True, "status": sender.get_status()}

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
    logger.log_event("system_startup", {
        'components': components,
        'startup_time': datetime.now().isoformat()
    })

def log_plugin_activity(plugin_name: str, action: str, details: Dict[str, Any] = None):
    """Log específico para actividad de plugins"""
    logger = get_logger("plugins")
    logger.log_event("plugin_activity", {
        'plugin_name': plugin_name,
        'action': action,
        'details': details or {}
    })


# =================== NEW WEB LOGGING FUNCTIONS ===================
def setup_web_logging(config_file: str = None, auto_configure: bool = True) -> Dict[str, Any]:
    """
    Configura el sistema de web logging para todo el antivirus
    
    Args:
        config_file: Archivo de configuración (opcional)
        auto_configure: Si configurar automáticamente todos los loggers
        
    Returns:
        Dict con resultado de la configuración
    """
    if not WEB_LOGGING_AVAILABLE:
        return {
            'success': False, 
            'errors': ['Web logging no disponible. Verificar instalación del módulo.'],
            'configured_loggers': []
        }
    
    try:
        if auto_configure:
            # Configurar todos los loggers del antivirus automáticamente
            return setup_antivirus_web_logging(
                config_file=config_file,
                logger_names=[
                    'antivirus_system',
                    'core', 
                    'plugins',
                    'ml_detector',
                    'behavior_detector', 
                    'network_detector',
                    'file_monitor',
                    'process_monitor',
                    'network_monitor'
                ]
            )
        else:
            # Solo verificar configuración
            manager = WebLogConfigManager(config_file)
            config = manager.get_config()
            
            return {
                'success': config.enabled and manager.validate_config(),
                'config': config.to_dict(),
                'errors': config.validate() if not manager.validate_config() else [],
                'configured_loggers': []
            }
            
    except Exception as e:
        return {
            'success': False,
            'errors': [f'Error configurando web logging: {e}'],
            'configured_loggers': []
        }


def enable_web_logging(api_url: str = "http://localhost:8000/api", 
                      api_key: str = "antivirus-system-key-2024",
                      level: str = "INFO") -> bool:
    """
    Habilita web logging con configuración específica
    
    Args:
        api_url: URL del API backend
        api_key: API key para autenticación
        level: Nivel mínimo de logging
        
    Returns:
        True si se habilitó exitosamente
    """
    if not WEB_LOGGING_AVAILABLE:
        print("❌ Web logging no disponible")
        return False
    
    try:
        # Actualizar configuración
        manager = WebLogConfigManager()
        manager.update_config(
            api_url=api_url,
            api_key=api_key,
            level=level,
            enabled=True
        )
        
        if manager.validate_config():
            manager.save_config()
            
            # Configurar loggers existentes
            result = setup_web_logging(auto_configure=True)
            
            if result['success']:
                print(f"✅ Web logging habilitado para {len(result['configured_loggers'])} loggers")
                return True
            else:
                print(f"❌ Error habilitando web logging: {result['errors']}")
                return False
        else:
            print("❌ Configuración inválida para web logging")
            return False
            
    except Exception as e:
        print(f"❌ Error habilitando web logging: {e}")
        return False


def disable_web_logging() -> bool:
    """
    Deshabilita web logging en todo el sistema
    
    Returns:
        True si se deshabilitó exitosamente
    """
    try:
        if WEB_LOGGING_AVAILABLE:
            manager = WebLogConfigManager()
            manager.disable_web_logging()
        
        # Remover WebLogHandlers de todos los loggers
        root_logger = logging.getLogger()
        
        def remove_web_handlers(logger):
            """Remueve WebLogHandlers recursivamente"""
            if WEB_LOGGING_AVAILABLE and WebLogHandler:
                # Remover handlers del logger actual
                handlers_to_remove = [
                    h for h in logger.handlers 
                    if isinstance(h, WebLogHandler)
                ]
                
                for handler in handlers_to_remove:
                    logger.removeHandler(handler)
                    handler.close()
                
                # Procesar loggers hijos
                for child_name, child_logger in logger.manager.loggerDict.items():
                    if isinstance(child_logger, logging.Logger):
                        remove_web_handlers(child_logger)
        
        remove_web_handlers(root_logger)
        print("🔒 Web logging deshabilitado")
        return True
        
    except Exception as e:
        print(f"❌ Error deshabilitando web logging: {e}")
        return False


def get_web_logging_info() -> Dict[str, Any]:
    """
    Obtiene información completa del estado del web logging
    
    Returns:
        Dict con información detallada
    """
    if not WEB_LOGGING_AVAILABLE:
        return {
            'available': False,
            'reason': 'Web logging module not available',
            'enabled': False,
            'handlers': 0,
            'loggers': []
        }
    
    try:
        status = get_web_logging_status()
        
        return {
            'available': True,
            'enabled': status.get('config_status', {}).get('enabled', False),
            'connectivity': status.get('connectivity', False),
            'handlers_active': status.get('handlers_active', 0),
            'loggers_configured': status.get('loggers_configured', []),
            'statistics': status.get('statistics', {}),
            'config_file': status.get('config_status', {}).get('config_file'),
            'api_url': status.get('config_status', {}).get('api_url'),
            'errors': status.get('errors', []),
            'last_updated': status.get('timestamp')
        }
        
    except Exception as e:
        return {
            'available': True,
            'enabled': False,
            'error': str(e),
            'handlers': 0,
            'loggers': []
        }


def test_web_logging_connection() -> bool:
    """
    Test de conectividad con el servidor web
    
    Returns:
        True si la conexión es exitosa
    """
    if not WEB_LOGGING_AVAILABLE:
        print("❌ Web logging no disponible")
        return False
    
    try:
        manager = WebLogConfigManager()
        return manager.test_connection()
    except Exception as e:
        print(f"❌ Error probando conexión: {e}")
        return False


def log_test_message(message: str = "Test de web logging desde antivirus", 
                    level: str = "INFO",
                    logger_name: str = "test") -> bool:
    """
    Envía un mensaje de prueba al sistema de web logging
    
    Args:
        message: Mensaje a enviar
        level: Nivel del log
        logger_name: Nombre del logger
        
    Returns:
        True si se envió exitosamente
    """
    try:
        logger = get_logger(logger_name)
        log_method = getattr(logger, level.lower())
        
        log_method(message, extra={
            'test': True,
            'timestamp': datetime.now().isoformat(),
            'system': 'antivirus_core'
        })
        
        print(f"✅ Mensaje de prueba enviado: {message}")
        return True
        
    except Exception as e:
        print(f"❌ Error enviando mensaje de prueba: {e}")
        return False


def setup_logger(name: str = "antivirus", level: str = "INFO") -> logging.Logger:
    """
    Función de compatibilidad para el frontend.
    Configura y retorna un logger usando la infraestructura existente.
    
    Args:
        name: Nombre del logger
        level: Nivel de logging
        
    Returns:
        Logger configurado
    """
    try:
        # Usar la función existente get_logger que ya configura todo
        logger = get_logger(name)
        
        # Establecer el nivel si se especifica
        if level.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            logger.setLevel(getattr(logging, level.upper()))
            
        return logger
        
    except Exception as e:
        print(f"⚠️ Error configurando logger, usando fallback: {e}")
        # Fallback básico si falla todo
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger