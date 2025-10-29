"""
Plugin File Monitor - Sistema de Monitoreo de Archivos
=====================================================

Implementación de Plugin para monitoreo avanzado del sistema de archivos con
detección de actividades sospechosas, cuarentena automática y análisis de contenido.

Características:
- Monitoreo en tiempo real de directorios críticos
- Detección de archivos sospechosos por contenido y comportamiento  
- Sistema de cuarentena automática
- Análisis de hashes y metadatos
- Integración completa con Event Bus y Registry

Design Patterns Implementados:
- Template Method: Para estructura de plugin base
- Observer: Mediante Event Bus para comunicación
- Strategy: Para diferentes estrategias de análisis
- Chain of Responsibility: Para procesamiento de eventos

Autor: Unified Antivirus Architecture
Versión: 3.1.0
Fecha: 2024-12-20
"""

import logging
import threading
import time
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Callable, Any
from collections import deque
import hashlib
import json

# Importar infraestructura del core
from core.base_plugin import BasePlugin, PluginInterface
from core.event_bus import Event

logger = logging.getLogger(__name__)


class FileMonitorAnalyzer:
    """Analizador especializado para archivos del sistema"""
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Patrones de detección
        self.suspicious_extensions = set(config.get('suspicious_extensions', [
            '.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd',
            '.vbs', '.js', '.jar', '.tmp', '.log'
        ]))
        
        self.suspicious_filenames = config.get('suspicious_filenames', [
            'keylog', 'password', 'credential', 'capture', 'spy',
            'hack', 'stealer', 'monitor', 'recorder', 'sniffer',
            'temp', 'cache', 'dump', 'backup'
        ])
        
        self.ignore_extensions = set(config.get('ignore_extensions', [
            '.jpg', '.png', '.gif', '.bmp', '.ico', '.mp3', '.mp4',
            '.avi', '.mkv', '.pdf', '.doc', '.docx', '.xlsx'
        ]))
        
        logger.info("[ANALYZER] File Monitor Analyzer inicializado")
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Análisis completo de un archivo"""
        try:
            return self._get_file_info(file_path)
        except Exception as e:
            logger.error(f"[ERROR] Error analizando archivo {file_path}: {e}")
            return {}
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Obtiene información detallada de un archivo"""
        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                return {}
                
            stat = path_obj.stat()
            
            info = {
                'path': file_path,
                'name': path_obj.name,
                'extension': path_obj.suffix.lower(),
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime,
                'is_hidden': self._is_hidden_file(file_path),
                'analysis_timestamp': datetime.now().timestamp()
            }
            
            # Hash del archivo (solo para archivos pequeños)
            if stat.st_size < 1024 * 1024:  # < 1MB
                info['hash'] = self._calculate_file_hash(file_path)
            
            # Análisis de contenido y riesgo
            info.update(self._analyze_file_content(file_path, info))
            
            return info
            
        except (OSError, FileNotFoundError, PermissionError):
            return {}
        except Exception as e:
            logger.debug(f"Error obteniendo info de {file_path}: {e}")
            return {}
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcula el hash SHA256 de un archivo"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""
    
    def _is_hidden_file(self, file_path: str) -> bool:
        """Verifica si un archivo está oculto"""
        try:
            import stat as stat_module
            return bool(os.stat(file_path).st_file_attributes & stat_module.FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            return Path(file_path).name.startswith('.')
    
    def _analyze_file_content(self, file_path: str, file_info: Dict) -> Dict[str, Any]:
        """Analiza el contenido del archivo para detectar patrones sospechosos"""
        analysis = {
            'is_executable': False,
            'has_suspicious_strings': False,
            'contains_credentials': False,
            'is_log_file': False,
            'risk_score': 0.0
        }
        
        try:
            extension = file_info.get('extension', '').lower()
            name = file_info.get('name', '').lower()
            
            # Verificar si es ejecutable
            if extension in self.suspicious_extensions:
                analysis['is_executable'] = True
                analysis['risk_score'] += 0.3
            
            # Verificar nombre sospechoso
            for suspicious in self.suspicious_filenames:
                if suspicious in name:
                    analysis['has_suspicious_strings'] = True
                    analysis['risk_score'] += 0.4
                    break
            
            # Análisis de contenido para archivos de texto pequeños
            if (extension in ['.txt', '.log', '.cfg', '.ini', '.conf'] and 
                file_info.get('size', 0) < 100 * 1024):  # < 100KB
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)  # Primeros 1000 caracteres
                        
                        # Buscar patrones de credenciales
                        credential_patterns = [
                            'password', 'passwd', 'pwd', 'user', 'login',
                            'credential', 'token', 'key', 'secret', 'auth'
                        ]
                        
                        content_lower = content.lower()
                        for pattern in credential_patterns:
                            if pattern in content_lower:
                                analysis['contains_credentials'] = True
                                analysis['risk_score'] += 0.5
                                break
                        
                        # Verificar si es archivo de log
                        if any(word in content_lower for word in ['log', 'event', 'timestamp', 'date']):
                            analysis['is_log_file'] = True
                            analysis['risk_score'] += 0.2
                            
                except Exception:
                    pass
            
            # Verificar ubicación sospechosa
            path_lower = file_path.lower()
            suspicious_locations = ['temp', 'tmp', 'cache', 'appdata\\local\\temp']
            if any(location in path_lower for location in suspicious_locations):
                analysis['risk_score'] += 0.2
            
        except Exception as e:
            logger.debug(f"Error analizando contenido de {file_path}: {e}")
        
        return analysis
    
    def is_suspicious_file(self, file_info: Dict) -> bool:
        """Determina si un archivo es sospechoso basado en múltiples criterios"""
        if not file_info:
            return False
            
        risk_score = file_info.get('risk_score', 0.0)
        
        # Criterios de sospecha múltiples
        suspicious_criteria = [
            risk_score > 0.6,
            file_info.get('has_suspicious_strings', False),
            file_info.get('contains_credentials', False),
            file_info.get('is_executable', False) and file_info.get('is_hidden', False),
            file_info.get('size', 0) == 0 and file_info.get('extension') in ['.exe', '.dll']
        ]
        
        return any(suspicious_criteria)


class QuarantineManager:
    """Gestor de cuarentena para archivos peligrosos"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.quarantine_dir = Path(config.get('quarantine_directory', 'C:\\Quarantine'))
        self.enabled = config.get('quarantine_enabled', True)
        self.quarantined_files = set()
        
        if self.enabled:
            self._ensure_quarantine_directory()
        
        logger.info(f"[QUARANTINE] Quarantine Manager {'habilitado' if self.enabled else 'deshabilitado'}")
    
    def _ensure_quarantine_directory(self):
        """Asegura que existe el directorio de cuarentena"""
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"[SECURITY] Directorio de cuarentena: {self.quarantine_dir}")
        except Exception as e:
            logger.error(f"[ERROR] Error creando directorio de cuarentena: {e}")
            self.enabled = False
    
    def quarantine_file(self, file_path: str, reason: str = "suspicious_detected") -> bool:
        """Pone un archivo en cuarentena"""
        if not self.enabled:
            return False
            
        try:
            source_path = Path(file_path)
            if not source_path.exists():
                return False
            
            # Crear nombre único en cuarentena
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{source_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Mover archivo a cuarentena
            source_path.rename(quarantine_path)
            
            # Crear archivo de metadatos
            metadata = {
                'original_path': str(source_path),
                'quarantine_time': datetime.now().isoformat(),
                'reason': reason,
                'file_hash': self._calculate_hash(str(quarantine_path))
            }
            
            metadata_path = quarantine_path.with_suffix(quarantine_path.suffix + '.metadata')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.quarantined_files.add(str(quarantine_path))
            
            logger.warning(f"[QUARANTINE] Archivo en cuarentena: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error en cuarentena: {e}")
            return False
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calcula hash del archivo"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""
    
    def restore_file(self, quarantine_path: str) -> bool:
        """Restaura un archivo de la cuarentena"""
        try:
            quarantine_file = Path(quarantine_path)
            metadata_file = quarantine_file.with_suffix(quarantine_file.suffix + '.metadata')
            
            if not quarantine_file.exists() or not metadata_file.exists():
                return False
            
            # Leer metadatos
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            original_path = Path(metadata['original_path'])
            
            # Restaurar archivo
            quarantine_file.rename(original_path)
            metadata_file.unlink()  # Eliminar metadatos
            
            self.quarantined_files.discard(quarantine_path)
            
            logger.info(f"[RESTORE] Archivo restaurado: {quarantine_path} -> {original_path}")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error restaurando archivo: {e}")
            return False
    
    def get_quarantined_files(self) -> List[str]:
        """Obtiene lista de archivos en cuarentena"""
        return list(self.quarantined_files)


class FileMonitorPlugin(BasePlugin, PluginInterface):
    """
    Plugin de Monitoreo de Archivos - Implementación Template Method
    
    Proporciona monitoreo en tiempo real del sistema de archivos con:
    - Detección de archivos sospechosos
    - Sistema de cuarentena automática  
    - Análisis de contenido y metadatos
    - Integración con Event Bus
    """
    
    def __init__(self):
        BasePlugin.__init__(self, "file_monitor", str(Path(__file__).parent))
        PluginInterface.__init__(self)
        self.plugin_type = "monitor"
        self.name = "file_monitor"
        self.version = "3.1.0"
        self.description = "Monitor avanzado del sistema de archivos con detección inteligente"
        
        # Componentes especializados
        self.analyzer = None
        self.quarantine_manager = None
        
        # Estado del monitoreo
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Buffer de eventos y tracking
        self.file_events = deque(maxlen=1000)
        self.tracked_files = {}  # path -> file_info
        self.suspicious_files = set()
        
        # Estadísticas
        self.stats = {
            'files_monitored': 0,
            'suspicious_files_detected': 0,
            'files_quarantined': 0,
            'events_processed': 0,
            'start_time': None,
            'last_scan': None
        }
        
        logger.info("[PLUGIN] FileMonitorPlugin inicializado")
    
    # Template Method Pattern - Métodos base requeridos
    
    def initialize(self) -> bool:
        """Inicialización del plugin - Template Method Step 1"""
        try:
            logger.info(f"[INIT] Inicializando {self.name} v{self.version}")
            
            # Configuración por defecto
            self.config = self._get_default_config()
            
            # Inicializar componentes especializados
            self.analyzer = FileMonitorAnalyzer(self.config)
            self.quarantine_manager = QuarantineManager(self.config)
            
            self._validate_monitored_directories()
            
            logger.info("[INIT] FileMonitorPlugin inicializado correctamente")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error inicializando FileMonitorPlugin: {e}")
            return False
    
    def configure(self, config: Dict) -> bool:
        """Configuración del plugin - Template Method Step 2"""
        try:
            logger.info("[CONFIG] Configurando FileMonitorPlugin")
            
            # Mergear con configuración por defecto
            self.config.update(config)
            
            # Reconfigurar componentes
            if self.analyzer:
                self.analyzer = FileMonitorAnalyzer(self.config)
            
            if self.quarantine_manager:
                self.quarantine_manager = QuarantineManager(self.config)
            
            self._validate_monitored_directories()
            
            logger.info("[CONFIG] FileMonitorPlugin configurado exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error configurando FileMonitorPlugin: {e}")
            return False
    
    def start(self) -> bool:
        """Inicio del plugin - Template Method Step 3"""
        try:
            if self.is_monitoring:
                logger.warning("[WARNING] FileMonitorPlugin ya está ejecutándose")
                return True
            
            logger.info("[START] Iniciando FileMonitorPlugin")
            
            self.is_monitoring = True
            self.stats['start_time'] = datetime.now()
            
            # Escaneo inicial
            self._initial_file_scan()
            
            # Iniciar hilo de monitoreo
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                name="FileMonitorPlugin",
                daemon=True
            )
            self.monitor_thread.start()
            
            # Publicar evento de inicio
            self._publish_event("plugin_started", {
                'plugin_name': self.name,
                'plugin_type': self.plugin_type,
                'version': self.version
            })
            
            logger.info("[START] FileMonitorPlugin iniciado exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error iniciando FileMonitorPlugin: {e}")
            self.is_monitoring = False
            return False
    
    def stop(self) -> bool:
        """Detención del plugin - Template Method Step 4"""
        try:
            if not self.is_monitoring:
                logger.warning("[WARNING] FileMonitorPlugin no está ejecutándose")
                return True
            
            logger.info("[STOP] Deteniendo FileMonitorPlugin")
            
            self.is_monitoring = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5.0)
            
            # Publicar evento de detención
            self._publish_event("plugin_stopped", {
                'plugin_name': self.name,
                'plugin_type': self.plugin_type,
                'stats': self.get_stats()
            })
            
            logger.info("[STOP] FileMonitorPlugin detenido exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error deteniendo FileMonitorPlugin: {e}")
            return False
    
    def cleanup(self) -> bool:
        """Limpieza del plugin - Template Method Step 5"""
        try:
            logger.info("[CLEANUP] Limpiando recursos de FileMonitorPlugin")
            
            # Asegurar que el monitoreo está detenido
            if self.is_monitoring:
                self.stop()
            
            # Limpiar buffers y estructuras
            self.file_events.clear()
            self.tracked_files.clear()
            self.suspicious_files.clear()
            
            # Resetear estadísticas
            self.stats = {
                'files_monitored': 0,
                'suspicious_files_detected': 0,
                'files_quarantined': 0,
                'events_processed': 0,
                'start_time': None,
                'last_scan': None
            }
            
            logger.info("[CLEANUP] Limpieza completada")
            return True
            
        except Exception as e:
            logger.error(f"[ERROR] Error en limpieza: {e}")
            return False
    
    # Métodos específicos del Plugin
    
    def _get_default_config(self) -> Dict:
        """Configuración por defecto del plugin"""
        return {
            'scan_interval': 5.0,  # segundos
            'monitored_directories': [
                str(Path.home()),  # Directorio del usuario
                'C:\\Windows\\Temp',
                'C:\\Temp',
                'C:\\Users\\Public',
                os.environ.get('APPDATA', ''),
                os.environ.get('LOCALAPPDATA', ''),
                os.environ.get('TEMP', ''),
            ],
            'suspicious_extensions': [
                '.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd',
                '.vbs', '.js', '.jar', '.tmp', '.log'
            ],
            'suspicious_filenames': [
                'keylog', 'password', 'credential', 'capture', 'spy',
                'hack', 'stealer', 'monitor', 'recorder', 'sniffer',
                'temp', 'cache', 'dump', 'backup'
            ],
            'ignore_extensions': [
                '.jpg', '.png', '.gif', '.bmp', '.ico', '.mp3', '.mp4',
                '.avi', '.mkv', '.pdf', '.doc', '.docx', '.xlsx'
            ],
            'max_file_size_mb': 100,
            'quarantine_enabled': True,
            'quarantine_directory': 'C:\\Quarantine',
            'auto_quarantine_threshold': 0.8
        }
    
    def _validate_monitored_directories(self):
        """Valida y filtra directorios monitoreados"""
        valid_dirs = []
        for directory in self.config.get('monitored_directories', []):
            if directory and os.path.exists(directory):
                valid_dirs.append(directory)
            else:
                logger.debug(f"[CONFIG] Directorio inválido ignorado: {directory}")
        
        self.config['monitored_directories'] = valid_dirs
        logger.info(f"[CONFIG] {len(valid_dirs)} directorios válidos para monitoreo")
    
    def _initial_file_scan(self):
        """Escaneo inicial de archivos existentes"""
        logger.info("[SCAN] Iniciando escaneo inicial de archivos...")
        
        total_files = 0
        for directory in self.config['monitored_directories']:
            try:
                for file_path in self._scan_directory(directory):
                    file_info = self.analyzer.analyze_file(file_path)
                    if file_info:
                        self.tracked_files[file_path] = file_info
                        total_files += 1
                        
                        # Verificar si es sospechoso
                        if self.analyzer.is_suspicious_file(file_info):
                            self._flag_suspicious_file(file_path, file_info, "archivo_existente_sospechoso")
                        
            except Exception as e:
                logger.error(f"[ERROR] Error escaneando {directory}: {e}")
        
        self.stats['files_monitored'] = total_files
        logger.info(f"[SCAN] Escaneo inicial completado: {total_files} archivos")
    
    def _scan_directory(self, directory: str, max_depth: int = 3) -> List[str]:
        """Escanea un directorio recursivamente con límites de seguridad"""
        files = []
        
        try:
            path_obj = Path(directory)
            if not path_obj.exists() or not path_obj.is_dir():
                return files
            
            # Escaneo recursivo con límite de profundidad
            for root, dirs, filenames in os.walk(directory):
                # Controlar profundidad
                depth = len(Path(root).relative_to(path_obj).parts)
                if depth > max_depth:
                    dirs.clear()  # No profundizar más
                    continue
                
                # Filtrar directorios del sistema que causan problemas
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d.lower() not in ['system volume information', '$recycle.bin']]
                
                for filename in filenames:
                    try:
                        file_path = os.path.join(root, filename)
                        if self._should_monitor_file(file_path):
                            files.append(file_path)
                    except Exception:
                        continue
                
                # Limitar número de archivos por directorio
                if len(files) > 10000:
                    break
                    
        except (PermissionError, OSError) as e:
            logger.debug(f"Sin acceso a {directory}: {e}")
        except Exception as e:
            logger.error(f"[ERROR] Error escaneando directorio {directory}: {e}")
        
        return files
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Determina si un archivo debe ser monitoreado"""
        try:
            path_obj = Path(file_path)
            
            # Verificar extensión
            extension = path_obj.suffix.lower()
            if extension in self.analyzer.ignore_extensions:
                return False
            
            # Verificar tamaño
            try:
                size_mb = path_obj.stat().st_size / (1024 * 1024)
                if size_mb > self.config.get('max_file_size_mb', 100):
                    return False
            except (OSError, FileNotFoundError):
                return False
            
            # Verificar si es archivo del sistema crítico
            system_paths = ['windows\\system32', 'windows\\syswow64', 'program files']
            file_path_lower = file_path.lower()
            if any(sys_path in file_path_lower for sys_path in system_paths):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _monitoring_loop(self):
        """Bucle principal de monitoreo continuo"""
        logger.info("[MONITOR] Iniciando bucle de monitoreo continuo...")
        
        while self.is_monitoring:
            try:
                self._scan_for_changes()
                time.sleep(self.config.get('scan_interval', 5.0))
                
            except Exception as e:
                logger.error(f"[ERROR] Error en bucle de monitoreo: {e}")
                time.sleep(10)  # Espera más larga en caso de error
    
    def _scan_for_changes(self):
        """Escanea cambios en archivos monitoreados"""
        self.stats['last_scan'] = datetime.now()
        changes_detected = 0
        
        # Verificar archivos existentes
        files_to_remove = []
        for file_path, old_info in list(self.tracked_files.items()):
            try:
                if not os.path.exists(file_path):
                    # Archivo eliminado
                    self._handle_file_deleted(file_path, old_info)
                    files_to_remove.append(file_path)
                    changes_detected += 1
                else:
                    # Verificar modificaciones
                    current_info = self.analyzer.analyze_file(file_path)
                    if current_info and self._file_changed(old_info, current_info):
                        self._handle_file_modified(file_path, old_info, current_info)
                        self.tracked_files[file_path] = current_info
                        changes_detected += 1
                        
            except Exception as e:
                logger.debug(f"Error verificando {file_path}: {e}")
        
        # Remover archivos eliminados del tracking
        for file_path in files_to_remove:
            del self.tracked_files[file_path]
        
        # Buscar archivos nuevos (limitar búsqueda para rendimiento)
        for directory in self.config['monitored_directories'][:3]:  # Solo 3 dirs por ciclo
            try:
                new_files = self._find_new_files(directory)
                for file_path in new_files:
                    file_info = self.analyzer.analyze_file(file_path)
                    if file_info:
                        self._handle_file_created(file_path, file_info)
                        self.tracked_files[file_path] = file_info
                        changes_detected += 1
                        
            except Exception as e:
                logger.debug(f"Error buscando nuevos archivos en {directory}: {e}")
        
        if changes_detected > 0:
            logger.debug(f"[ACTIVITY] Detectados {changes_detected} cambios en archivos")
    
    def _find_new_files(self, directory: str) -> List[str]:
        """Encuentra archivos nuevos en un directorio (escaneo superficial)"""
        new_files = []
        
        try:
            # Solo escaneo de primer nivel para rendimiento
            for item in os.listdir(directory):
                file_path = os.path.join(directory, item)
                
                if (os.path.isfile(file_path) and 
                    file_path not in self.tracked_files and
                    self._should_monitor_file(file_path)):
                    
                    new_files.append(file_path)
                    
                    # Limitar nuevos archivos por ciclo
                    if len(new_files) >= 20:
                        break
                        
        except (PermissionError, OSError, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug(f"Error buscando nuevos archivos: {e}")
        
        return new_files
    
    def _file_changed(self, old_info: Dict, new_info: Dict) -> bool:
        """Verifica si un archivo ha cambiado significativamente"""
        return (old_info.get('modified', 0) != new_info.get('modified', 0) or
                old_info.get('size', 0) != new_info.get('size', 0))
    
    def _handle_file_created(self, file_path: str, file_info: Dict):
        """Maneja la detección de un archivo nuevo"""
        event = {
            'type': 'file_created',
            'path': file_path,
            'file_info': file_info,
            'timestamp': datetime.now().isoformat(),
            'plugin': self.name
        }
        
        self.file_events.append(event)
        self.stats['events_processed'] += 1
        
        # Verificar si es sospechoso
        if self.analyzer.is_suspicious_file(file_info):
            self._flag_suspicious_file(file_path, file_info, "archivo_nuevo_sospechoso")
        
        # Publicar evento al Event Bus
        self._publish_event("file_created", event)
        
        logger.debug(f"[CREATE] Archivo creado: {file_path}")
    
    def _handle_file_modified(self, file_path: str, old_info: Dict, new_info: Dict):
        """Maneja la modificación de un archivo"""
        event = {
            'type': 'file_modified',
            'path': file_path,
            'old_info': old_info,
            'new_info': new_info,
            'timestamp': datetime.now().isoformat(),
            'plugin': self.name
        }
        
        self.file_events.append(event)
        self.stats['events_processed'] += 1
        
        # Verificar si se volvió sospechoso
        if not self.analyzer.is_suspicious_file(old_info) and self.analyzer.is_suspicious_file(new_info):
            self._flag_suspicious_file(file_path, new_info, "archivo_modificado_sospechoso")
        
        # Publicar evento al Event Bus
        self._publish_event("file_modified", event)
        
        logger.debug(f"[MODIFY] Archivo modificado: {file_path}")
    
    def _handle_file_deleted(self, file_path: str, file_info: Dict):
        """Maneja la eliminación de un archivo"""
        event = {
            'type': 'file_deleted',
            'path': file_path,
            'file_info': file_info,
            'timestamp': datetime.now().isoformat(),
            'plugin': self.name
        }
        
        self.file_events.append(event)
        self.stats['events_processed'] += 1
        
        # Remover de archivos sospechosos
        self.suspicious_files.discard(file_path)
        
        # Publicar evento al Event Bus
        self._publish_event("file_deleted", event)
        
        logger.debug(f"[DELETE] Archivo eliminado: {file_path}")
    
    def _flag_suspicious_file(self, file_path: str, file_info: Dict, reason: str):
        """Marca y procesa un archivo sospechoso"""
        if file_path not in self.suspicious_files:
            self.suspicious_files.add(file_path)
            self.stats['suspicious_files_detected'] += 1
            
            # Crear evento de amenaza
            threat_data = {
                'type': 'suspicious_file',
                'path': file_path,
                'file_info': file_info,
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
                'risk_score': file_info.get('risk_score', 0.0),
                'plugin': self.name,
                'severity': self._calculate_severity(file_info.get('risk_score', 0.0))
            }
            
            logger.warning(f"[THREAT] Archivo sospechoso: {file_path} - {reason} (score: {file_info.get('risk_score', 0):.2f})")
            
            # Cuarentena automática para archivos de alto riesgo
            auto_threshold = self.config.get('auto_quarantine_threshold', 0.8)
            if (self.quarantine_manager.enabled and 
                file_info.get('risk_score', 0.0) >= auto_threshold):
                
                if self.quarantine_manager.quarantine_file(file_path, reason):
                    threat_data['quarantined'] = True
                    self.stats['files_quarantined'] += 1
                    logger.warning(f"[AUTO-QUARANTINE] Archivo automaticamente puesto en cuarentena: {file_path}")
            
            # Publicar evento de amenaza al Event Bus
            self._publish_event("threat_detected", threat_data)
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calcula la severidad basada en el score de riesgo"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "info"
    
    def _publish_event(self, event_type: str, data: Dict):
        """Publica un evento al Event Bus"""
        try:
            if self.event_bus:
                event = Event(
                    type=event_type,
                    source=self.name,
                    data=data,
                    timestamp=datetime.now().isoformat()
                )
                self.event_bus.publish(event)
        except Exception as e:
            logger.debug(f"Error publicando evento {event_type}: {e}")
    
    # Métodos de API pública
    
    def get_recent_data(self, count: Optional[int] = None) -> List[Dict]:
        """Obtiene eventos recientes de archivos"""
        if count is None:
            return list(self.file_events)
        else:
            return list(self.file_events)[-count:]
    
    def get_suspicious_files(self) -> List[str]:
        """Obtiene lista de archivos sospechosos activos"""
        return list(self.suspicious_files)
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas completas del monitor"""
        stats = self.stats.copy()
        stats.update({
            'suspicious_files_active': len(self.suspicious_files),
            'quarantined_files': len(self.quarantine_manager.get_quarantined_files()),
            'tracked_files': len(self.tracked_files),
            'is_monitoring': self.is_monitoring,
            'plugin_name': self.name,
            'plugin_version': self.version
        })
        
        if stats['start_time']:
            uptime = (datetime.now() - stats['start_time']).total_seconds()
            stats['uptime_seconds'] = uptime
            stats['uptime_formatted'] = str(datetime.now() - stats['start_time']).split('.')[0]
        
        return stats
    
    def is_active(self) -> bool:
        """Verifica si el plugin está activo y monitoreando"""
        return self.is_monitoring and self.monitor_thread and self.monitor_thread.is_alive()
    
    def quarantine_file(self, file_path: str, reason: str = "manual_quarantine") -> bool:
        """API para poner manualmente un archivo en cuarentena"""
        if self.quarantine_manager:
            success = self.quarantine_manager.quarantine_file(file_path, reason)
            if success:
                self.stats['files_quarantined'] += 1
                # Remover del tracking
                self.tracked_files.pop(file_path, None)
                self.suspicious_files.discard(file_path)
            return success
        return False
    
    def restore_file(self, quarantine_path: str) -> bool:
        """API para restaurar un archivo de la cuarentena"""
        if self.quarantine_manager:
            return self.quarantine_manager.restore_file(quarantine_path)
        return False
    
    def get_quarantined_files(self) -> List[str]:
        """Obtiene lista de archivos en cuarentena"""
        if self.quarantine_manager:
            return self.quarantine_manager.get_quarantined_files()
        return []
    
    def force_scan(self):
        """Fuerza un escaneo inmediato"""
        if self.is_monitoring:
            logger.info("[FORCE-SCAN] Ejecutando escaneo forzado...")
            self._scan_for_changes()
            logger.info("[FORCE-SCAN] Escaneo forzado completado")
    
    def get_plugin_info(self) -> Dict:
        """Información completa del plugin"""
        return {
            'name': self.name,
            'type': self.plugin_type,
            'version': self.version,
            'description': self.description,
            'is_active': self.is_active(),
            'capabilities': [
                'file_monitoring',
                'threat_detection',
                'automatic_quarantine',
                'content_analysis',
                'hash_calculation',
                'metadata_extraction',
                'directory_scanning',
                'event_publishing'
            ],
            'config': {
                'monitored_directories': len(self.config.get('monitored_directories', [])),
                'scan_interval': self.config.get('scan_interval', 5.0),
                'quarantine_enabled': self.config.get('quarantine_enabled', False),
                'auto_quarantine_threshold': self.config.get('auto_quarantine_threshold', 0.8)
            }
        }
    
    # Métodos requeridos por PluginInterface (Observer Pattern)
    
    def on_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Maneja eventos del event bus"""
        try:
            if event_type == "system_shutdown":
                logger.info("[EVENT] Recibido evento de shutdown del sistema")
                self.stop()
            
            elif event_type == "configuration_updated":
                logger.info("[EVENT] Recibida actualización de configuración")
                new_config = data.get('config', {})
                if 'file_monitor' in new_config:
                    self.configure(new_config['file_monitor'])
            
            elif event_type == "quarantine_update":
                logger.info("[EVENT] Recibida actualización de cuarentena")
                enabled = data.get('enabled', True)
                max_size = data.get('max_size_mb', 100)
                self.update_quarantine_settings(enabled, max_size)
            
            elif event_type == "force_file_scan":
                logger.info("[EVENT] Recibido comando de escaneo forzado")
                self.force_scan()
            
            else:
                logger.debug(f"[EVENT] Evento no manejado: {event_type}")
        
        except Exception as e:
            logger.error(f"[ERROR] Error manejando evento {event_type}: {e}")
    
    def publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publica eventos al event bus"""
        self._publish_event(event_type, data)
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Información específica del FileMonitorPlugin"""
        return {
            'name': self.name,
            'version': self.version,
            'type': self.plugin_type,
            'description': self.description,
            'status': 'active' if self.is_monitoring else 'inactive',
            'capabilities': [
                'file_system_monitoring',
                'real_time_file_analysis',
                'hash_calculation',
                'automatic_quarantine',
                'suspicious_file_detection',
                'file_integrity_checking',
                'malware_scanning',
                'behavioral_file_analysis'
            ],
            'stats': self.get_stats(),
            'config_summary': {
                'monitored_directories': len(self.config.get('monitored_directories', [])),
                'scan_interval': self.config.get('scan_interval', 5.0),
                'quarantine_enabled': self.config.get('quarantine_enabled', False),
                'auto_quarantine_threshold': self.config.get('auto_quarantine_threshold', 0.8)
            }
        }


def test_file_monitor_plugin():
    """Función de test integrado para el File Monitor Plugin"""
    import sys
    import os
    
    # Agregar el directorio core al path para importar las interfaces
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core'))
    
    def mock_event_callback(event):
        print(f"📢 Evento recibido: {event.type} desde {event.source}")
        if event.type == "threat_detected":
            data = event.data
            print(f"   🚨 AMENAZA: {data.get('path', 'N/A')}")
            print(f"   📊 Risk Score: {data.get('risk_score', 0):.2f}")
            print(f"   ⚡ Severidad: {data.get('severity', 'N/A')}")
            if data.get('quarantined'):
                print(f"   🔒 ARCHIVO EN CUARENTENA AUTOMÁTICA")
    
    print("🧪 ===== TEST FILE MONITOR PLUGIN =====")
    
    try:
        # Crear plugin
        plugin = FileMonitorPlugin()
        
        # Configuración de test
        test_config = {
            'scan_interval': 2.0,  # Más rápido para test
            'monitored_directories': [
                str(Path.home() / 'Desktop'),  # Directorio más pequeño para test
                os.environ.get('TEMP', 'C:\\Temp')
            ],
            'quarantine_enabled': True,
            'auto_quarantine_threshold': 0.7  # Más sensible para test
        }
        
        # Simular event bus simple
        class MockEventBus:
            def __init__(self, callback):
                self.callback = callback
            
            def publish(self, event):
                if self.callback:
                    self.callback(event)
        
        plugin.event_bus = MockEventBus(mock_event_callback)
        
        # Test del ciclo de vida completo
        print("\n1️⃣ Inicializando plugin...")
        assert plugin.initialize(), "❌ Error en initialize()"
        print("✅ Plugin inicializado")
        
        print("\n2️⃣ Configurando plugin...")
        assert plugin.configure(test_config), "❌ Error en configure()"
        print("✅ Plugin configurado")
        
        print("\n3️⃣ Iniciando plugin...")
        assert plugin.start(), "❌ Error en start()"
        print("✅ Plugin iniciado")
        
        print("\n4️⃣ Verificando estado...")
        assert plugin.is_active(), "❌ Plugin no está activo"
        print("✅ Plugin activo y monitoreando")
        
        print("\n5️⃣ Ejecutando monitoreo por 20 segundos...")
        for i in range(10):
            time.sleep(2)
            stats = plugin.get_stats()
            print(f"   [{i*2+2:2d}s] Archivos: {stats['tracked_files']}, Sospechosos: {stats['suspicious_files_active']}, Eventos: {stats['events_processed']}")
            
            # Mostrar archivos sospechosos si hay
            suspicious = plugin.get_suspicious_files()
            if suspicious:
                print(f"        🚨 {len(suspicious)} archivos sospechosos detectados")
        
        print("\n6️⃣ Información del plugin:")
        info = plugin.get_plugin_info()
        print(f"   📋 Nombre: {info['name']} v{info['version']}")
        print(f"   🔧 Capacidades: {len(info['capabilities'])}")
        print(f"   📁 Directorios: {info['config']['monitored_directories']}")
        
        print("\n7️⃣ Estadísticas finales:")
        final_stats = plugin.get_stats()
        for key, value in final_stats.items():
            if key not in ['start_time']:
                print(f"   {key}: {value}")
        
        print("\n8️⃣ Deteniendo plugin...")
        assert plugin.stop(), "❌ Error en stop()"
        print("✅ Plugin detenido")
        
        print("\n9️⃣ Limpiando recursos...")
        assert plugin.cleanup(), "❌ Error en cleanup()"
        print("✅ Recursos limpiados")
        
        print("\n🎉 ¡Test exitoso! File Monitor Plugin funciona correctamente")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error durante el test: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    except KeyboardInterrupt:
        print("\n⏹️ Test interrumpido por usuario")
        if 'plugin' in locals():
            plugin.stop()
            plugin.cleanup()
        return False





if __name__ == "__main__":
    # Ejecutar test si se ejecuta directamente
    test_file_monitor_plugin()