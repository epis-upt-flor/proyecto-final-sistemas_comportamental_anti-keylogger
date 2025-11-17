"""
Sistema de Logs en Tiempo Real
==============================

Proporciona acceso a logs reales del sistema antivirus en tiempo real.
Reemplaza los datos fake con información real del backend.
"""

import os
import time
import threading
import logging
from typing import List, Dict, Any, Optional, Generator
from collections import deque
from datetime import datetime
import json
import re
from pathlib import Path

logger = logging.getLogger(__name__)

class RealTimeLogReader:
    """Lector de logs en tiempo real"""
    
    def __init__(self, log_file_path: str, max_entries: int = 1000):
        self.log_file_path = log_file_path
        self.max_entries = max_entries
        self.log_entries = deque(maxlen=max_entries)
        
        self.is_monitoring = False
        self.monitoring_thread = None
        self.file_position = 0
        
        # Filtros de log
        self.level_filter = "ALL"
        self.search_filter = ""
        
        # Estadísticas
        self.total_entries = 0
        self.last_update = 0
        
        logger.info(f"RealTimeLogReader inicializado para {log_file_path}")
    
    def start_monitoring(self):
        """Inicia el monitoreo del archivo de log"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        
        # Cargar logs existentes
        self._load_existing_logs()
        
        # Iniciar monitoreo en tiempo real
        self.monitoring_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name=f"LogMonitor-{os.path.basename(self.log_file_path)}"
        )
        self.monitoring_thread.start()
        
        logger.info(f"✅ Monitoreo de logs iniciado para {self.log_file_path}")
    
    def stop_monitoring(self):
        """Detiene el monitoreo"""
        self.is_monitoring = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2.0)
        logger.info(f"🛑 Monitoreo de logs detenido para {self.log_file_path}")
    
    def _load_existing_logs(self):
        """Carga los logs existentes del archivo"""
        try:
            if not os.path.exists(self.log_file_path):
                logger.warning(f"Archivo de log no existe: {self.log_file_path}")
                return
            
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Leer las últimas líneas del archivo
                lines = f.readlines()
                
                # Procesar solo las últimas 100 líneas para empezar
                recent_lines = lines[-100:] if len(lines) > 100 else lines
                
                for line in recent_lines:
                    parsed_entry = self._parse_log_line(line.strip())
                    if parsed_entry:
                        self.log_entries.append(parsed_entry)
                        self.total_entries += 1
                
                self.file_position = f.tell()
                self.last_update = time.time()
                
            logger.info(f"Cargadas {len(recent_lines)} entradas de log existentes")
            
        except Exception as e:
            logger.error(f"Error cargando logs existentes: {e}")
    
    def _monitor_loop(self):
        """Loop de monitoreo en tiempo real"""
        while self.is_monitoring:
            try:
                if os.path.exists(self.log_file_path):
                    with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.file_position)
                        
                        for line in f:
                            if not self.is_monitoring:
                                break
                                
                            parsed_entry = self._parse_log_line(line.strip())
                            if parsed_entry:
                                self.log_entries.append(parsed_entry)
                                self.total_entries += 1
                                self.last_update = time.time()
                        
                        self.file_position = f.tell()
                
                time.sleep(0.5)  # Verificar cada 0.5 segundos
                
            except Exception as e:
                logger.debug(f"Error en loop de monitoreo: {e}")
                time.sleep(1)
    
    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parsea una línea de log y extrae información estructurada"""
        if not line or line.startswith('#'):
            return None
            
        try:
            # Patrón básico: 2025-11-08 22:42:16,538 - ModuleName - LEVEL - Message
            log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - ([^-]+) - (\w+) - (.+)'
            match = re.match(log_pattern, line)
            
            if match:
                timestamp_str, module, level, message = match.groups()
                
                # Convertir timestamp
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f').timestamp()
                
                # Categorizar el mensaje
                category = self._categorize_message(message, module)
                severity = self._determine_severity(level, message)
                
                return {
                    'timestamp': timestamp,
                    'datetime': timestamp_str,
                    'module': module.strip(),
                    'level': level.strip(),
                    'message': message.strip(),
                    'category': category,
                    'severity': severity,
                    'raw_line': line
                }
            else:
                # Fallback para líneas que no coincidan con el patrón
                return {
                    'timestamp': time.time(),
                    'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
                    'module': 'unknown',
                    'level': 'INFO',
                    'message': line,
                    'category': 'general',
                    'severity': 'info',
                    'raw_line': line
                }
                
        except Exception as e:
            logger.debug(f"Error parseando línea de log: {e}")
            return None
    
    def _categorize_message(self, message: str, module: str) -> str:
        """Categoriza el mensaje de log"""
        message_lower = message.lower()
        module_lower = module.lower()
        
        if any(word in message_lower for word in ['keylogger', '🚨', 'detectado', 'detected', 'threat']):
            return 'threat_detection'
        elif any(word in message_lower for word in ['plugin', 'activado', 'activated', 'inicializado']):
            return 'plugin_activity'
        elif any(word in message_lower for word in ['scan', 'escaneo', 'analysis']):
            return 'scanning'
        elif any(word in message_lower for word in ['network', 'connection', 'conexión']):
            return 'network'
        elif any(word in message_lower for word in ['error', 'exception', 'failed']):
            return 'error'
        elif any(word in message_lower for word in ['warning', 'advertencia']):
            return 'warning'
        elif any(word in module_lower for word in ['ui', 'frontend', 'interface']):
            return 'ui'
        else:
            return 'system'
    
    def _determine_severity(self, level: str, message: str) -> str:
        """Determina la severidad basada en el nivel y contenido"""
        level_lower = level.lower()
        message_lower = message.lower()
        
        if level_lower == 'error' or any(word in message_lower for word in ['crítico', 'critical', 'fatal']):
            return 'critical'
        elif level_lower == 'warning' or any(word in message_lower for word in ['⚠️', 'warning', 'advertencia']):
            return 'warning'
        elif any(word in message_lower for word in ['🚨', 'threat', 'amenaza', 'detectado']):
            return 'alert'
        elif level_lower == 'info':
            return 'info'
        elif level_lower == 'debug':
            return 'debug'
        else:
            return 'info'
    
    def get_filtered_logs(self, level_filter: str = "ALL", search_filter: str = "", 
                         max_entries: int = None) -> List[Dict[str, Any]]:
        """Obtiene logs filtrados"""
        try:
            logs = list(self.log_entries)
            
            # Filtro por nivel
            if level_filter != "ALL":
                level_map = {
                    "ERROR": ['ERROR', 'critical'],
                    "WARNING": ['WARNING', 'warning', 'alert'],
                    "INFO": ['INFO', 'info'],
                    "DEBUG": ['DEBUG', 'debug']
                }
                
                if level_filter in level_map:
                    allowed_levels = level_map[level_filter]
                    logs = [log for log in logs if log.get('level') in allowed_levels or 
                           log.get('severity') in allowed_levels]
            
            # Filtro por búsqueda
            if search_filter:
                search_lower = search_filter.lower()
                logs = [log for log in logs if search_lower in log.get('message', '').lower() or
                       search_lower in log.get('module', '').lower()]
            
            # Limitar número de entradas
            if max_entries:
                logs = logs[-max_entries:]
            
            # Ordenar por timestamp (más recientes primero)
            logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            
            return logs
            
        except Exception as e:
            logger.error(f"Error filtrando logs: {e}")
            return []
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de los logs"""
        try:
            logs = list(self.log_entries)
            
            # Contar por categoría
            categories = {}
            severities = {}
            modules = {}
            
            for log in logs:
                cat = log.get('category', 'unknown')
                sev = log.get('severity', 'unknown')
                mod = log.get('module', 'unknown')
                
                categories[cat] = categories.get(cat, 0) + 1
                severities[sev] = severities.get(sev, 0) + 1
                modules[mod] = modules.get(mod, 0) + 1
            
            # Logs recientes (última hora)
            recent_threshold = time.time() - 3600
            recent_logs = [log for log in logs if log.get('timestamp', 0) > recent_threshold]
            
            return {
                'total_entries': self.total_entries,
                'current_entries': len(logs),
                'recent_entries': len(recent_logs),
                'last_update': self.last_update,
                'categories': categories,
                'severities': severities,
                'modules': modules,
                'monitoring_active': self.is_monitoring
            }
            
        except Exception as e:
            logger.error(f"Error calculando estadísticas: {e}")
            return {}

class LogManager:
    """Gestor principal de logs del sistema"""
    
    def __init__(self):
        self.log_readers = {}
        self.available_log_files = {}
        self.current_reader = None
        
        # Buscar archivos de log disponibles
        self._discover_log_files()
        
        logger.info("LogManager inicializado")
    
    def _discover_log_files(self):
        """Descubre archivos de log disponibles"""
        log_locations = [
            'logs/',
            '.',
            '../logs/',
            'C:/temp/',
            '/tmp/'
        ]
        
        log_patterns = [
            '*.log',
            'antivirus*.log',
            'engine*.log',
            '*.jsonl'
        ]
        
        for location in log_locations:
            if os.path.exists(location):
                for pattern in log_patterns:
                    import glob
                    full_pattern = os.path.join(location, pattern)
                    
                    for log_file in glob.glob(full_pattern):
                        if os.path.isfile(log_file):
                            name = os.path.basename(log_file)
                            self.available_log_files[name] = os.path.abspath(log_file)
        
        # Archivos específicos conocidos
        known_logs = {
            'antivirus_engine.log': 'logs/antivirus.log',
            'system.log': 'logs/system.log', 
            'debug.log': 'logs/debug.log'
        }
        
        for name, path in known_logs.items():
            if os.path.exists(path):
                self.available_log_files[name] = os.path.abspath(path)
        
        logger.info(f"Descubiertos {len(self.available_log_files)} archivos de log")
    
    def get_available_log_files(self) -> Dict[str, str]:
        """Obtiene archivos de log disponibles"""
        return self.available_log_files.copy()
    
    def select_log_file(self, log_name: str) -> bool:
        """Selecciona un archivo de log para monitorear"""
        try:
            if log_name not in self.available_log_files:
                logger.error(f"Archivo de log no encontrado: {log_name}")
                return False
            
            # Detener lector actual si existe
            if self.current_reader:
                self.current_reader.stop_monitoring()
            
            # Crear nuevo lector
            log_path = self.available_log_files[log_name]
            self.current_reader = RealTimeLogReader(log_path)
            self.current_reader.start_monitoring()
            
            logger.info(f"✅ Seleccionado archivo de log: {log_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error seleccionando archivo de log: {e}")
            return False
    
    def get_current_logs(self, **kwargs) -> List[Dict[str, Any]]:
        """Obtiene logs del lector actual"""
        if not self.current_reader:
            return []
        
        return self.current_reader.get_filtered_logs(**kwargs)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del lector actual"""
        if not self.current_reader:
            return {}
        
        return self.current_reader.get_log_statistics()
    
    def refresh_available_logs(self):
        """Refresca la lista de archivos disponibles"""
        self._discover_log_files()

# Instancia global del gestor de logs
_log_manager_instance = None

def get_log_manager() -> LogManager:
    """Obtiene la instancia global del gestor de logs"""
    global _log_manager_instance
    if _log_manager_instance is None:
        _log_manager_instance = LogManager()
    return _log_manager_instance