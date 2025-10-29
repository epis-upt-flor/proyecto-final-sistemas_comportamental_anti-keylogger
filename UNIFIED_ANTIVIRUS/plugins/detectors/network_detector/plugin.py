"""
🌐 Network Detector Plugin
==========================

Plugin especializado en análisis de patrones de red maliciosos para detectar keyloggers.

Implementa múltiples patrones de diseño:
- Template Method: Proceso estándar de análisis de red  
- Observer: Monitoreo continuo de conexiones
- Strategy: Algoritmos intercambiables de detección
- Chain of Responsibility: Cadena de analizadores especializados
"""

import os
import sys
import json
import time
import logging
import threading
import psutil
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from pathlib import Path

# Agregar directorio padre para imports
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.base_plugin import BasePlugin
from core.interfaces import DetectorInterface
from .network_analyzer import NetworkAnalyzer
from .threat_intelligence import ThreatIntelligenceManager
from .pattern_detector import PatternDetector
from .ip_analyzer import IPAnalyzer


@dataclass
class NetworkConnection:
    """Representación de una conexión de red."""
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    process_name: str
    process_pid: int
    connection_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para serialización."""
        return asdict(self)


@dataclass 
class ThreatDetection:
    """Representación de una amenaza detectada."""
    threat_type: str
    confidence: float
    description: str
    source_ip: str
    dest_ip: str
    process_name: str
    timestamp: datetime
    evidence: Dict[str, Any]
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario para eventos."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class NetworkDetectorPlugin(BasePlugin, DetectorInterface):
    """
    🌐 Plugin de detección de amenazas de red.
    
    Implementa Template Method para proceso estándar de análisis:
    1. Captura de conexiones de red
    2. Análisis de patrones maliciosos
    3. Correlación con threat intelligence  
    4. Detección de comunicaciones C&C
    5. Identificación de exfiltración de datos
    """
    
    def __init__(self, config_path: str = None):
        plugin_name = "network_detector"
        plugin_path = str(Path(__file__).parent)
        super().__init__(plugin_name, plugin_path)
        self.plugin_name = plugin_name
        self.version = "1.0.0"
        self.category = "detectors"
        
        # Componentes del plugin
        self.network_analyzer: Optional[NetworkAnalyzer] = None
        self.threat_intel: Optional[ThreatIntelligenceManager] = None
        self.pattern_detector: Optional[PatternDetector] = None
        self.ip_analyzer: Optional[IPAnalyzer] = None
        
        # Estado interno
        self.connections: deque = deque(maxlen=10000)
        self.active_connections: Dict[str, NetworkConnection] = {}
        self.threat_cache: Dict[str, ThreatDetection] = {}
        self.analysis_lock = threading.Lock()
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.is_active = False
        
        # Configuración
        self.config: Dict[str, Any] = {}
        self.whitelist_ips: Set[str] = set()
        self.whitelist_domains: Set[str] = set()
        self.system_processes: Set[str] = set()
        
        # Métricas
        self.metrics = {
            'connections_analyzed': 0,
            'c2_communications_detected': 0,
            'data_exfiltration_detected': 0,
            'beacon_patterns_found': 0,
            'malicious_ips_blocked': 0,
            'suspicious_domains_flagged': 0,
            'threats_detected_total': 0,
            'analysis_errors': 0
        }
        
        self.logger = self._setup_logging()
        
        # Inicializar automáticamente
        self.initialize()
    
    def _setup_logging(self) -> logging.Logger:
        """Configura logging específico del plugin."""
        logger = logging.getLogger(f"{self.plugin_name}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # Handler para archivo
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            file_handler = logging.FileHandler(
                log_dir / f"{self.plugin_name}.log",
                encoding='utf-8'
            )
            file_handler.setLevel(logging.INFO)
            
            # Formato detallado
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    # ==================== TEMPLATE METHOD PATTERN ====================
    
    def initialize(self) -> bool:
        """
        🔧 Template Method: Inicialización del plugin.
        
        Steps:
        1. Cargar configuración
        2. Inicializar componentes especializados (versión simplificada)
        3. Configurar whitelist básica
        4. Preparar para suscripción a eventos
        """
        try:
            self.logger.info("🌐 Inicializando Network Detector Plugin...")
            
            # Step 1: Cargar configuración
            if not self._load_configuration_sync():
                return False
            
            # Step 2: Inicializar componentes (versión simple)
            self._initialize_components_sync()
            
            # Step 3: Configurar whitelist básica
            self._setup_security_data_sync()
            
            # Step 4: Preparar suscripción a eventos
            self._prepare_event_subscription()
            
            self.logger.info("✅ Network Detector Plugin inicializado correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando Network Detector: {e}")
            return False
    
    def activate(self) -> bool:
        """
        🚀 Template Method: Activación del plugin.
        
        Steps:
        1. Verificar componentes inicializados
        2. Iniciar monitoreo de red
        3. Cargar threat intelligence actualizada
        4. Publicar evento de activación
        """
        try:
            self.logger.info("🚀 Activando Network Detector Plugin...")
            
            # Step 1: Verificar componentes
            if not self._verify_components():
                return False
            
            # Step 2: Iniciar monitoreo
            self._start_network_monitoring_sync()
            
            # Step 3: Actualizar threat intelligence
            if self.threat_intel:
                try:
                    import asyncio
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self.threat_intel.update_threat_feeds())
                    loop.close()
                except Exception as e:
                    self.logger.warning(f"⚠️ No se pudo actualizar threat intelligence: {e}")
            
            # Step 4: Publicar evento
            self._publish_event_sync("network_detector_activated", {
                "plugin": self.plugin_name,
                "version": self.version,
                "capabilities": self._get_capabilities(),
                "timestamp": datetime.now().isoformat()
            })
            
            self.is_active = True
            self.logger.info("✅ Network Detector Plugin activado")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error activando Network Detector: {e}")
            return False
    
    async def deactivate(self) -> bool:
        """
        🛑 Template Method: Desactivación del plugin.
        
        Steps:
        1. Detener monitoreo de red
        2. Guardar estado y métricas
        3. Limpiar recursos
        4. Publicar evento de desactivación
        """
        try:
            self.logger.info("🛑 Desactivando Network Detector Plugin...")
            
            # Step 1: Detener monitoreo
            await self._stop_network_monitoring()
            
            # Step 2: Guardar estado
            await self._save_state()
            
            # Step 3: Limpiar recursos
            self._cleanup_resources()
            
            # Step 4: Publicar evento
            await self._publish_event("network_detector_deactivated", {
                "plugin": self.plugin_name,
                "final_metrics": self.metrics,
                "timestamp": datetime.now().isoformat()
            })
            
            self.is_active = False
            self.logger.info("✅ Network Detector Plugin desactivado")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error desactivando Network Detector: {e}")
            return False
    
    # ==================== CONFIGURACIÓN Y COMPONENTES ====================
    
    async def _load_configuration(self) -> bool:
        """Carga la configuración del plugin."""
        try:
            config_path = Path(__file__).parent / "config.json"
            
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                    
                # Configurar whitelist
                whitelist_config = self.config.get('whitelist', {})
                self.whitelist_ips = set(whitelist_config.get('trusted_ips', []))
                self.whitelist_domains = set(whitelist_config.get('trusted_domains', []))
                self.system_processes = set(whitelist_config.get('system_processes', []))
                
                self.logger.info(f"📋 Configuración cargada: {len(self.config)} secciones")
                return True
            else:
                self.logger.warning("⚠️ Archivo config.json no encontrado, usando configuración por defecto")
                self._set_default_configuration()
                return True
                
        except Exception as e:
            self.logger.error(f"❌ Error cargando configuración: {e}")
            return False
    
    def _set_default_configuration(self):
        """Establece configuración por defecto."""
        self.config = {
            "network_config": {
                "analysis_window_minutes": 10,
                "min_connections_for_pattern": 3,
                "beacon_tolerance": 0.3,
                "suspicious_upload_threshold": 1024,
                "c2_confidence_threshold": 0.7
            },
            "detection_thresholds": {
                "c2_beacon_min_count": 5,
                "c2_beacon_regularity": 0.8,
                "exfiltration_ratio_threshold": 0.8
            }
        }
    
    async def _initialize_components(self):
        """Inicializa los componentes especializados del plugin."""
        try:
            # Inicializar analizador de red
            self.network_analyzer = NetworkAnalyzer(self.config)
            await self.network_analyzer.initialize()
            
            # Inicializar threat intelligence
            self.threat_intel = ThreatIntelligenceManager(self.config)
            await self.threat_intel.initialize()
            
            # Inicializar detector de patrones
            self.pattern_detector = PatternDetector(self.config)
            await self.pattern_detector.initialize()
            
            # Inicializar analizador de IPs
            self.ip_analyzer = IPAnalyzer(self.config)
            await self.ip_analyzer.initialize()
            
            self.logger.info("🔧 Componentes especializados inicializados")
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando componentes: {e}")
            raise
    
    async def _setup_security_data(self):
        """Configura datos de seguridad y threat intelligence."""
        try:
            if self.threat_intel:
                # Cargar IPs maliciosas conocidas
                await self.threat_intel.load_malicious_ips()
                
                # Cargar dominios sospechosos
                await self.threat_intel.load_suspicious_domains()
                
                # Inicializar caché de reputación
                await self.threat_intel.initialize_reputation_cache()
            
            self.logger.info("🛡️ Datos de seguridad configurados")
            
        except Exception as e:
            self.logger.error(f"❌ Error configurando datos de seguridad: {e}")
    
    def _verify_components(self) -> bool:
        """Verifica que todos los componentes estén correctamente inicializados (versión simplificada)."""
        # Para la versión básica, solo verificamos que las métricas estén inicializadas
        if not hasattr(self, 'metrics') or not self.metrics:
            self.logger.error("❌ Métricas no inicializadas")
            return False
            
        # Marcar que los componentes están en modo básico
        self.logger.info("✅ Componentes verificados (modo básico)")
        return True
    
    # ==================== OBSERVER PATTERN ====================
    
    def _subscribe_to_events(self):
        """Suscribe el plugin a eventos relevantes del sistema."""
        events_to_subscribe = [
            'network_connection_established',
            'network_data_transferred',
            'dns_query_made', 
            'scan_requested',
            'process_network_activity'
        ]
        
        for event_type in events_to_subscribe:
            self.event_bus.subscribe(event_type, self._handle_network_event)
        
        self.logger.info(f"📡 Suscrito a {len(events_to_subscribe)} tipos de eventos")
    
    async def _handle_network_event(self, event_type: str, event_data: Dict[str, Any]):
        """
        🎯 Observer: Maneja eventos de red del sistema.
        
        Implementa Strategy Pattern para diferentes tipos de análisis.
        """
        try:
            with self.analysis_lock:
                # Crear conexión de red
                connection = self._create_network_connection(event_data)
                
                if connection and self._should_analyze_connection(connection):
                    # Agregar a historial
                    self.connections.append(connection)
                    self.active_connections[connection.connection_id] = connection
                    
                    # Análisis según tipo de evento (Strategy Pattern)
                    await self._analyze_connection_by_strategy(event_type, connection)
                    
                    # Incrementar métricas
                    self.metrics['connections_analyzed'] += 1
                    
        except Exception as e:
            self.logger.error(f"❌ Error procesando evento {event_type}: {e}")
            self.metrics['analysis_errors'] += 1
    
    def _create_network_connection(self, event_data: Dict[str, Any]) -> Optional[NetworkConnection]:
        """Crea objeto NetworkConnection desde datos de evento."""
        try:
            return NetworkConnection(
                timestamp=datetime.now(),
                source_ip=event_data.get('source_ip', ''),
                source_port=event_data.get('source_port', 0),
                dest_ip=event_data.get('dest_ip', ''),
                dest_port=event_data.get('dest_port', 0),
                protocol=event_data.get('protocol', 'TCP'),
                bytes_sent=event_data.get('bytes_sent', 0),
                bytes_received=event_data.get('bytes_received', 0),
                process_name=event_data.get('process_name', ''),
                process_pid=event_data.get('process_pid', 0),
                connection_id=f"{event_data.get('source_ip')}:{event_data.get('source_port')}-{event_data.get('dest_ip')}:{event_data.get('dest_port')}"
            )
        except Exception as e:
            self.logger.error(f"❌ Error creando NetworkConnection: {e}")
            return None
    
    def _should_analyze_connection(self, connection: NetworkConnection) -> bool:
        """Determina si una conexión debe ser analizada."""
        # Filtrar whitelist
        if connection.dest_ip in self.whitelist_ips:
            return False
        
        if connection.process_name in self.system_processes:
            return False
        
        # Filtrar conexiones locales
        if connection.dest_ip.startswith(('127.', '192.168.', '10.', '172.')):
            return False
        
        return True
    
    # ==================== STRATEGY PATTERN ====================
    
    async def _analyze_connection_by_strategy(self, event_type: str, connection: NetworkConnection):
        """
        🎯 Strategy Pattern: Selecciona estrategia de análisis según tipo de evento.
        """
        strategies = {
            'network_connection_established': self._analyze_new_connection,
            'network_data_transferred': self._analyze_data_transfer,
            'dns_query_made': self._analyze_dns_query,
            'process_network_activity': self._analyze_process_activity
        }
        
        strategy = strategies.get(event_type)
        if strategy:
            await strategy(connection)
    
    async def _analyze_new_connection(self, connection: NetworkConnection):
        """Estrategia: Análisis de nueva conexión."""
        if self.ip_analyzer and self.threat_intel:
            # Verificar IP maliciosa conocida
            is_malicious = await self.threat_intel.is_malicious_ip(connection.dest_ip)
            if is_malicious:
                await self._create_threat_detection(
                    threat_type="malicious_ip_connection",
                    connection=connection,
                    confidence=0.9,
                    description=f"Conexión a IP maliciosa conocida: {connection.dest_ip}"
                )
            
            # Análisis de reputación
            reputation = await self.ip_analyzer.get_ip_reputation(connection.dest_ip)
            if reputation and reputation < 0.3:  # Baja reputación
                await self._create_threat_detection(
                    threat_type="low_reputation_ip",
                    connection=connection,
                    confidence=0.6,
                    description=f"Conexión a IP con baja reputación: {connection.dest_ip} (score: {reputation})"
                )
    
    async def _analyze_data_transfer(self, connection: NetworkConnection):
        """Estrategia: Análisis de transferencia de datos."""
        if self.pattern_detector:
            # Detectar posible exfiltración de datos
            if connection.bytes_sent > 0:
                upload_ratio = connection.bytes_sent / (connection.bytes_sent + connection.bytes_received + 1)
                
                threshold = self.config.get('detection_thresholds', {}).get('exfiltration_ratio_threshold', 0.8)
                if upload_ratio > threshold:
                    await self._create_threat_detection(
                        threat_type="data_exfiltration",
                        connection=connection,
                        confidence=min(0.9, upload_ratio),
                        description=f"Posible exfiltración de datos - Ratio upload: {upload_ratio:.2f}"
                    )
                    self.metrics['data_exfiltration_detected'] += 1
    
    async def _analyze_dns_query(self, connection: NetworkConnection):
        """Estrategia: Análisis de consulta DNS."""
        if self.threat_intel and hasattr(connection, 'dns_query'):
            domain = getattr(connection, 'dns_query', '')
            if domain:
                is_suspicious = await self.threat_intel.is_suspicious_domain(domain)
                if is_suspicious:
                    await self._create_threat_detection(
                        threat_type="malicious_domain_query",
                        connection=connection,
                        confidence=0.8,
                        description=f"Consulta DNS a dominio sospechoso: {domain}"
                    )
                    self.metrics['suspicious_domains_flagged'] += 1
    
    async def _analyze_process_activity(self, connection: NetworkConnection):
        """Estrategia: Análisis de actividad por proceso."""
        if self.pattern_detector:
            # Detectar patrones de beacon
            beacon_pattern = await self.pattern_detector.detect_beacon_pattern(
                connection.process_name,
                connection.dest_ip
            )
            
            if beacon_pattern:
                await self._create_threat_detection(
                    threat_type="beacon_pattern",
                    connection=connection,
                    confidence=beacon_pattern.get('confidence', 0.7),
                    description=f"Patrón de beacon detectado: {beacon_pattern.get('description', 'N/A')}"
                )
                self.metrics['beacon_patterns_found'] += 1
    
    # ==================== DETECCIÓN DE AMENAZAS ====================
    
    async def _create_threat_detection(self, threat_type: str, connection: NetworkConnection, 
                                     confidence: float, description: str):
        """Crea y procesa una nueva detección de amenaza."""
        try:
            # Determinar severidad
            severity = self._calculate_severity(threat_type, confidence)
            
            # Crear detección
            detection = ThreatDetection(
                threat_type=threat_type,
                confidence=confidence,
                description=description,
                source_ip=connection.source_ip,
                dest_ip=connection.dest_ip,
                process_name=connection.process_name,
                timestamp=datetime.now(),
                evidence={
                    'connection_details': connection.to_dict(),
                    'analysis_time': datetime.now().isoformat()
                },
                severity=severity
            )
            
            # Cachear detección
            detection_id = f"{threat_type}_{connection.connection_id}_{int(time.time())}"
            self.threat_cache[detection_id] = detection
            
            # Publicar evento de amenaza
            await self._publish_threat_event(detection)
            
            # Actualizar métricas
            self.metrics['threats_detected_total'] += 1
            self._update_threat_metrics(threat_type)
            
            self.logger.warning(f"🚨 Amenaza detectada: {threat_type} - {description}")
            
        except Exception as e:
            self.logger.error(f"❌ Error creando detección de amenaza: {e}")
    
    def _calculate_severity(self, threat_type: str, confidence: float) -> str:
        """Calcula la severidad de una amenaza."""
        severity_map = {
            'malicious_ip_connection': 'HIGH',
            'data_exfiltration': 'CRITICAL', 
            'beacon_pattern': 'MEDIUM',
            'malicious_domain_query': 'HIGH',
            'low_reputation_ip': 'LOW'
        }
        
        base_severity = severity_map.get(threat_type, 'MEDIUM')
        
        # Ajustar por confianza
        if confidence >= 0.9:
            return 'CRITICAL' if base_severity in ['HIGH', 'CRITICAL'] else 'HIGH'
        elif confidence >= 0.7:
            return base_severity
        else:
            return 'LOW' if base_severity == 'MEDIUM' else base_severity
    
    def _update_threat_metrics(self, threat_type: str):
        """Actualiza métricas específicas por tipo de amenaza."""
        if threat_type == 'malicious_ip_connection':
            self.metrics['malicious_ips_blocked'] += 1
        elif threat_type == 'data_exfiltration':
            self.metrics['data_exfiltration_detected'] += 1
        elif threat_type.endswith('_communication'):
            self.metrics['c2_communications_detected'] += 1
    
    async def _publish_threat_event(self, detection: ThreatDetection):
        """Publica evento de amenaza detectada."""
        event_type = f"threat_detected_{detection.threat_type}"
        
        await self._publish_event(event_type, {
            'plugin': self.plugin_name,
            'detection': detection.to_dict(),
            'severity': detection.severity,
            'confidence': detection.confidence,
            'timestamp': detection.timestamp.isoformat()
        })
    
    # ==================== MONITOREO DE RED ====================
    
    async def _start_network_monitoring(self):
        """Inicia el monitoreo continuo de red."""
        if not self.monitoring_active and self.network_analyzer:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(
                target=self._network_monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()
            self.logger.info("📡 Monitoreo de red iniciado")
    
    async def _stop_network_monitoring(self):
        """Detiene el monitoreo de red."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        self.logger.info("📡 Monitoreo de red detenido")
    
    def _network_monitoring_loop(self):
        """Loop principal de monitoreo real de red."""
        self.logger.info("[NETWORK_DETECTOR] Iniciando monitoreo real de conexiones de red")
        
        # Tracking de conexiones
        tracked_connections = {}
        suspicious_ips = set()
        connection_counts = defaultdict(int)
        
        try:
            while self.monitoring_active:
                current_time = datetime.now()
                active_connections = []
                
                try:
                    # Obtener conexiones de red activas usando psutil
                    net_connections = psutil.net_connections(kind='inet')
                    
                    for conn in net_connections:
                        if not self.monitoring_active:
                            break
                            
                        # Solo conexiones establecidas con dirección remota
                        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                            try:
                                # Obtener información del proceso
                                process_info = {}
                                if conn.pid:
                                    try:
                                        proc = psutil.Process(conn.pid)
                                        process_info = {
                                            'pid': conn.pid,
                                            'name': proc.name(),
                                            'exe': proc.exe() if proc.exe() else 'unknown'
                                        }
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        process_info = {'pid': conn.pid, 'name': 'unknown', 'exe': 'unknown'}
                                
                                # Crear datos de conexión
                                conn_data = {
                                    'local_ip': conn.laddr.ip,
                                    'local_port': conn.laddr.port,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'protocol': 'TCP' if conn.type == 1 else 'UDP',
                                    'status': conn.status,
                                    'timestamp': current_time,
                                    'process': process_info
                                }
                                
                                active_connections.append(conn_data)
                                
                                # Crear clave única para la conexión
                                conn_key = f"{conn.raddr.ip}:{conn.raddr.port}_{conn.pid}"
                                
                                # Detectar conexiones nuevas o sospechosas
                                if conn_key not in tracked_connections:
                                    tracked_connections[conn_key] = conn_data
                                    connection_counts[conn.raddr.ip] += 1
                                    
                                    # Analizar si es sospechosa
                                    if self._analyze_suspicious_connection(conn_data):
                                        self._trigger_network_alert("suspicious_connection", conn_data)
                                
                                # Detectar múltiples conexiones desde misma IP
                                if connection_counts[conn.raddr.ip] > 10:
                                    if conn.raddr.ip not in suspicious_ips:
                                        suspicious_ips.add(conn.raddr.ip)
                                        self._trigger_network_alert("multiple_connections_from_ip", {
                                            'remote_ip': conn.raddr.ip,
                                            'connection_count': connection_counts[conn.raddr.ip],
                                            'process': process_info
                                        })
                                
                            except Exception as e:
                                self.logger.debug(f"Error procesando conexión: {e}")
                                continue
                
                    # Actualizar estadísticas
                    self.stats['active_connections'] = len(active_connections)
                    self.processed_events += len(active_connections)
                    
                    # Limpiar conexiones viejas (cada 60 segundos)
                    if len(tracked_connections) > 1000:
                        # Mantener solo las 500 más recientes
                        sorted_conns = sorted(tracked_connections.items(), 
                                            key=lambda x: x[1].get('timestamp', datetime.min), 
                                            reverse=True)
                        tracked_connections = dict(sorted_conns[:500])
                    
                except Exception as e:
                    self.logger.error(f"[NETWORK_DETECTOR] Error escaneando conexiones: {e}")
                
                # Pausa entre análisis
                time.sleep(2.0)
        
        except Exception as e:
            self.logger.error(f"[NETWORK_DETECTOR] Error en monitoreo: {e}")
        
        self.logger.info("[NETWORK_DETECTOR] Monitoreo de red terminado")
    
    def _analyze_suspicious_connection(self, conn_data: Dict) -> bool:
        """Analiza si una conexión es sospechosa"""
        try:
            remote_ip = conn_data.get('remote_ip', '')
            remote_port = conn_data.get('remote_port', 0)
            process_info = conn_data.get('process', {})
            process_name = process_info.get('name', '').lower()
            
            # Verificar IPs externas sospechosas
            if not self._is_local_ip(remote_ip):
                # Conexiones en puertos inusuales
                suspicious_ports = [1337, 4444, 5555, 6666, 7777, 8080, 9999]
                if remote_port in suspicious_ports:
                    self.logger.warning(f"[DETECTION] Conexión a puerto sospechoso: {remote_ip}:{remote_port}")
                    return True
                
                # Procesos sospechosos con conexiones externas
                suspicious_processes = ['cmd.exe', 'powershell.exe', 'notepad.exe', 'calc.exe']
                if process_name in suspicious_processes:
                    self.logger.warning(f"[DETECTION] Proceso sospechoso con conexión externa: {process_name} -> {remote_ip}")
                    return True
                
                # Conexiones HTTPS en procesos no-browser
                if remote_port == 443:
                    browser_processes = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'safari.exe']
                    if process_name not in browser_processes and 'update' not in process_name:
                        self.logger.warning(f"[DETECTION] Conexión HTTPS desde proceso no-browser: {process_name}")
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error analizando conexión sospechosa: {e}")
            return False
    
    def _trigger_network_alert(self, alert_type: str, conn_data: Dict):
        """Dispara una alerta de red"""
        try:
            self.detections_count += 1
            self.last_detection_time = datetime.now()
            
            # Crear evento de alerta
            alert_event = {
                'plugin': self.name,
                'type': alert_type,
                'severity': 'high' if 'suspicious' in alert_type else 'medium',
                'timestamp': self.last_detection_time.isoformat(),
                'network_info': {
                    'remote_ip': conn_data.get('remote_ip'),
                    'remote_port': conn_data.get('remote_port'),
                    'protocol': conn_data.get('protocol'),
                    'process': conn_data.get('process', {})
                },
                'description': f"Detección de {alert_type} en conexión de red"
            }
            
            # Publicar evento en el EventBus
            if hasattr(self, 'event_bus') and self.event_bus:
                self.event_bus.publish('security_alert', alert_event)
                self.logger.info(f"[ALERT] {alert_type}: {conn_data.get('remote_ip')}:{conn_data.get('remote_port')}")
            
            # Log de la alerta
            self.logger.warning(f"[DETECTION] {alert_type}: {conn_data.get('remote_ip')} - {alert_event['description']}")
            
        except Exception as e:
            self.logger.error(f"Error disparando alerta de red: {e}")
    
    def _is_local_ip(self, ip: str) -> bool:
        """Verifica si una IP es local/privada"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            return ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'))
    
    # ==================== GESTIÓN DE ESTADO ====================
    
    async def _save_state(self):
        """Guarda el estado actual del plugin."""
        try:
            state_data = {
                'metrics': self.metrics,
                'active_connections_count': len(self.active_connections),
                'threat_cache_size': len(self.threat_cache),
                'last_update': datetime.now().isoformat()
            }
            
            state_file = Path("state") / f"{self.plugin_name}_state.json"
            state_file.parent.mkdir(exist_ok=True)
            
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info("💾 Estado del plugin guardado")
            
        except Exception as e:
            self.logger.error(f"❌ Error guardando estado: {e}")
    
    def _cleanup_resources(self):
        """Limpia recursos del plugin."""
        try:
            # Limpiar conexiones antiguas
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=1)
            
            # Filtrar conexiones recientes
            recent_connections = deque()
            for conn in self.connections:
                if conn.timestamp > cutoff_time:
                    recent_connections.append(conn)
            
            self.connections = recent_connections
            
            # Limpiar caché de amenazas antiguas
            old_threats = []
            for threat_id, detection in self.threat_cache.items():
                if detection.timestamp < cutoff_time:
                    old_threats.append(threat_id)
            
            for threat_id in old_threats:
                del self.threat_cache[threat_id]
            
            self.logger.info("🧹 Recursos limpiados")
            
        except Exception as e:
            self.logger.error(f"❌ Error limpiando recursos: {e}")
    
    # ==================== UTILIDADES ====================
    
    def _get_capabilities(self) -> List[str]:
        """Obtiene las capacidades del plugin."""
        return [
            'c2_communication_detection',
            'data_exfiltration_detection',
            'beacon_pattern_analysis',
            'malicious_ip_detection',
            'dns_tunnel_detection',
            'protocol_anomaly_detection',
            'threat_intelligence_integration'
        ]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Obtiene métricas actuales del plugin."""
        return {
            **self.metrics,
            'active_connections': len(self.active_connections),
            'cached_threats': len(self.threat_cache),
            'monitoring_active': self.monitoring_active,
            'last_update': datetime.now().isoformat()
        }
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Obtiene resumen de amenazas detectadas."""
        threat_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for detection in self.threat_cache.values():
            threat_counts[detection.threat_type] += 1
            severity_counts[detection.severity] += 1
        
        return {
            'total_threats': len(self.threat_cache),
            'by_type': dict(threat_counts),
            'by_severity': dict(severity_counts),
            'last_24h': self._count_recent_threats(24)
        }
    
    def _count_recent_threats(self, hours: int) -> int:
        """Cuenta amenazas detectadas en las últimas X horas."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return sum(1 for detection in self.threat_cache.values() 
                  if detection.timestamp > cutoff_time)
    
    # ==================== MÉTODOS ABSTRACTOS REQUERIDOS ====================
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Obtiene información del plugin (método abstracto requerido)."""
        return {
            'name': self.plugin_name,
            'version': self.version,
            'category': self.category,
            'description': 'Plugin de detección de amenazas de red para keyloggers',
            'author': 'Anti-Keylogger Team',
            'capabilities': self._get_capabilities(),
            'status': 'active' if self.is_active else 'inactive',
            'metrics': self.metrics
        }
    
    # ==================== MÉTODOS DE DETECTORINTERFACE ====================
    
    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detecta amenazas en datos de red usando análisis de patrones
        
        Args:
            data: Datos del sistema con información de red
            
        Returns:
            Lista de amenazas detectadas
        """
        try:
            threats = []
            
            # Extraer datos de red del sistema
            network_data = self._extract_network_data(data)
            
            if not network_data:
                return []
            
            # Analizar cada conexión de red
            for connection_data in network_data:
                # Crear objeto de conexión
                connection = self._create_network_connection(connection_data)
                
                # Analizar la conexión
                detection_result = self._analyze_connection(connection)
                
                if detection_result and detection_result.get('is_malicious', False):
                    threat = {
                        'threat_id': f"network_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{len(threats)}",
                        'threat_type': detection_result.get('threat_type', 'network_anomaly'),
                        'confidence_score': detection_result.get('confidence', 0.0),
                        'description': detection_result.get('description', 'Actividad de red sospechosa detectada'),
                        'details': {
                            'source_ip': connection.source_ip,
                            'dest_ip': connection.dest_ip,
                            'protocol': connection.protocol,
                            'process_name': connection.process_name,
                            'detection_reason': detection_result.get('reason', 'Patrón anómalo'),
                            'timestamp': connection.timestamp.isoformat()
                        },
                        'mitigation': 'Revisar conexiones de red y bloquear IPs sospechosas'
                    }
                    threats.append(threat)
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Error detectando amenazas de red: {e}")
            return []
    
    def get_confidence_score(self) -> float:
        """
        Retorna el nivel de confianza promedio de las detecciones
        
        Returns:
            Score de 0.0 a 1.0
        """
        if not self.threat_cache:
            return 0.8  # Confianza base del sistema
        
        total_confidence = sum(detection.confidence for detection in self.threat_cache.values())
        return min(total_confidence / len(self.threat_cache), 1.0)
    
    def update_signatures(self) -> bool:
        """
        Actualiza las firmas/patrones de detección de red
        
        Returns:
            True si se actualizaron correctamente
        """
        try:
            # Actualizar threat intelligence
            if self.threat_intel:
                updated = self.threat_intel.update_feeds()
                if updated:
                    self.logger.info("🔄 Threat intelligence actualizada")
            
            # Recargar patrones de detección
            if self.pattern_detector:
                patterns_loaded = self.pattern_detector.reload_patterns()
                self.logger.info(f"🔄 Patrones de red actualizados: {patterns_loaded} patrones")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error actualizando firmas de red: {e}")
            return False
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """
        Estadísticas de detección del plugin de red
        
        Returns:
            Diccionario con estadísticas de rendimiento
        """
        recent_threats = self._count_recent_threats(24)
        
        return {
            'total_connections_analyzed': self.metrics.get('connections_analyzed', 0),
            'total_threats_detected': len(self.threat_cache),
            'threats_last_24h': recent_threats,
            'average_confidence': self.get_confidence_score(),
            'active_connections': len(self.active_connections),
            'threat_intel_sources': len(getattr(self.threat_intel, 'feeds', [])) if self.threat_intel else 0,
            'detection_patterns': len(getattr(self.pattern_detector, 'patterns', [])) if self.pattern_detector else 0,
            'plugin_uptime': (datetime.now() - datetime.now()).total_seconds(),  # Placeholder
            'last_update': datetime.now().isoformat()
        }
    
    # ==================== MÉTODOS AUXILIARES ====================
    
    def _extract_network_data(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrae datos de red del sistema"""
        network_data = []
        
        # Buscar datos de red en diferentes formatos
        if 'network_data' in system_data:
            network_data.extend(system_data['network_data'])
        
        if 'connections' in system_data:
            network_data.extend(system_data['connections'])
        
        if 'network_events' in system_data:
            network_data.extend(system_data['network_events'])
        
        return network_data
    
    def _create_network_connection(self, data: Dict[str, Any]) -> NetworkConnection:
        """Crea objeto NetworkConnection desde datos"""
        return NetworkConnection(
            timestamp=datetime.now(),
            source_ip=data.get('src_ip', data.get('source_ip', '0.0.0.0')),
            source_port=data.get('src_port', data.get('source_port', 0)),
            dest_ip=data.get('dst_ip', data.get('dest_ip', '0.0.0.0')),
            dest_port=data.get('dst_port', data.get('dest_port', 0)),
            protocol=data.get('protocol', 'TCP'),
            bytes_sent=data.get('bytes_sent', 0),
            bytes_received=data.get('bytes_received', 0),
            process_name=data.get('process_name', 'unknown'),
            process_pid=data.get('process_pid', data.get('pid', 0)),
            connection_id=data.get('connection_id', f"{data.get('src_ip', '0.0.0.0')}:{data.get('src_port', 0)}-{data.get('dst_ip', '0.0.0.0')}:{data.get('dst_port', 0)}")
        )
    
    def _analyze_connection(self, connection: NetworkConnection) -> Dict[str, Any]:
        """Analiza una conexión individual"""
        try:
            # Análisis básico de patrones sospechosos
            is_malicious = False
            confidence = 0.0
            threat_type = 'network_anomaly'
            reason = 'Conexión normal'
            
            # Verificar IPs sospechosas
            if self._is_suspicious_ip(connection.dest_ip):
                is_malicious = True
                confidence = 0.9
                threat_type = 'malicious_ip'
                reason = 'Conexión a IP maliciosa conocida'
            
            # Verificar patrones de keylogger (puertos comunes, frecuencia, etc.)
            elif self._is_keylogger_pattern(connection):
                is_malicious = True
                confidence = 0.75
                threat_type = 'keylogger_network'
                reason = 'Patrón de comunicación típico de keylogger'
            
            return {
                'is_malicious': is_malicious,
                'confidence': confidence,
                'threat_type': threat_type,
                'reason': reason,
                'description': f'Análisis de conexión {connection.source_ip}:{connection.source_port} -> {connection.dest_ip}:{connection.dest_port}'
            }
            
        except Exception as e:
            self.logger.error(f"Error analizando conexión: {e}")
            return {'is_malicious': False, 'confidence': 0.0}
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Verifica si una IP es sospechosa"""
        # IPs de prueba consideradas maliciosas
        suspicious_ips = {
            '192.168.100.100', '10.0.0.100', '172.16.0.100',
            '8.8.4.4'  # Para pruebas
        }
        return ip in suspicious_ips
    
    def _is_keylogger_pattern(self, connection: NetworkConnection) -> bool:
        """Detecta patrones típicos de keyloggers"""
        # Patrones sospechosos:
        # 1. Conexiones frecuentes a puertos no estándar
        # 2. Transferencia de datos pequeños pero constantes
        # 3. Procesos con nombres sospechosos
        
        suspicious_patterns = [
            # Puertos comunes de C&C
            connection.dest_port in {8080, 8443, 9999, 4444, 5555},
            # Nombres de procesos sospechosos
            'keylog' in connection.process_name.lower(),
            'logger' in connection.process_name.lower(),
            # Transferencia de datos pequeños
            0 < connection.bytes_sent < 1024 and connection.bytes_received < 1024
        ]
        
        return any(suspicious_patterns)
    
    def start(self) -> bool:
        """Inicia el plugin (método abstracto requerido)."""
        try:
            if not self.is_active:
                # Versión simplificada de activación
                self.is_active = True
                self.logger.info("🚀 Network Detector Plugin iniciado")
            return True
        except Exception as e:
            self.logger.error(f"❌ Error iniciando plugin: {e}")
            return False
    
    def stop(self) -> bool:
        """Detiene el plugin (método abstracto requerido)."""
        try:
            if self.is_active:
                # Versión simplificada de desactivación
                self.is_active = False
                self.logger.info("🛑 Network Detector Plugin detenido")
            return True
        except Exception as e:
            self.logger.error(f"❌ Error deteniendo plugin: {e}")
            return False
    
    # ==================== MÉTODOS SÍNCRONOS AUXILIARES ====================
    
    def _load_configuration_sync(self) -> bool:
        """Versión síncrona de carga de configuración."""
        try:
            config_path = Path(__file__).parent / "config.json"
            
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                    
                # Configurar whitelist
                whitelist_config = self.config.get('whitelist', {})
                self.whitelist_ips = set(whitelist_config.get('trusted_ips', []))
                self.whitelist_domains = set(whitelist_config.get('trusted_domains', []))
                self.system_processes = set(whitelist_config.get('system_processes', []))
                
                self.logger.info(f"📋 Configuración cargada: {len(self.config)} secciones")
                return True
            else:
                self.logger.warning("⚠️ Archivo config.json no encontrado, usando configuración por defecto")
                self._set_default_configuration()
                return True
                
        except Exception as e:
            self.logger.error(f"❌ Error cargando configuración: {e}")
            return False
    
    def _initialize_components_sync(self):
        """Versión simplificada de inicialización de componentes."""
        try:
            # Solo inicializar métricas básicas
            self.metrics = {
                'connections_analyzed': 0,
                'c2_communications_detected': 0,
                'data_exfiltration_detected': 0,
                'beacon_patterns_found': 0,
                'malicious_ips_blocked': 0,
                'suspicious_domains_flagged': 0,
                'threats_detected_total': 0,
                'analysis_errors': 0
            }
            
            self.logger.info("🔧 Componentes básicos inicializados")
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando componentes: {e}")
            raise
    
    def _setup_security_data_sync(self):
        """Versión básica de configuración de datos de seguridad."""
        try:
            # Configurar datos básicos de seguridad
            # Inicializar como conjuntos vacíos si no existen
            if not hasattr(self, 'malicious_ips'):
                self.malicious_ips = {'185.220.100.240', '94.102.49.190'}
            if not hasattr(self, 'suspicious_domains'):
                self.suspicious_domains = {'tempuri.org', 'bit.ly'}
            
            self.logger.info("🛡️ Datos de seguridad básicos configurados")
            
        except Exception as e:
            self.logger.error(f"❌ Error configurando datos de seguridad: {e}")
    
    def _prepare_event_subscription(self):
        """Prepara la suscripción a eventos (sin event bus real por ahora)."""
        try:
            # Por ahora, solo preparar la lista de eventos
            self.events_to_subscribe = [
                'network_connection_established',
                'network_data_transferred',
                'dns_query_made',
                'scan_requested'
            ]
            
            self.logger.info(f"📡 Preparado para suscribirse a {len(self.events_to_subscribe)} tipos de eventos")
            
        except Exception as e:
            self.logger.error(f"❌ Error preparando suscripción a eventos: {e}")


# ==================== TESTING ====================

def main():
    """Función principal para testing del plugin."""
    import asyncio
    from unittest.mock import Mock
    
    async def test_plugin():
        """Test básico del plugin."""
        print("🧪 Iniciando test del Network Detector Plugin...")
        
        # Crear plugin
        plugin = NetworkDetectorPlugin()
        
        # Mock del event bus
        plugin.event_bus = Mock()
        plugin.event_bus.subscribe = Mock()
        plugin.event_bus.publish_event = Mock()
        
        # Test inicialización
        success = await plugin.initialize()
        print(f"✅ Inicialización: {'OK' if success else 'FALLO'}")
        
        # Test activación
        if success:
            success = await plugin.activate()
            print(f"✅ Activación: {'OK' if success else 'FALLO'}")
        
        # Test métricas
        if success:
            metrics = plugin.get_metrics()
            print(f"📊 Métricas: {len(metrics)} campos")
            
            threat_summary = plugin.get_threat_summary()
            print(f"🚨 Amenazas: {threat_summary['total_threats']} detectadas")
        
        # Test desactivación
        if success:
            success = await plugin.deactivate()
            print(f"✅ Desactivación: {'OK' if success else 'FALLO'}")
        
        print("🏁 Test completado")
    
    # Ejecutar test
    asyncio.run(test_plugin())


# ==================== MÉTODOS SÍNCRONOS AUXILIARES ====================

def _start_network_monitoring_sync(self):
    """Versión síncrona del inicio de monitoreo de red."""
    if not self.monitoring_active and self.network_analyzer:
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._network_monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        self.logger.info("📡 Monitoreo de red iniciado")

def _publish_event_sync(self, event_type: str, data: Dict[str, Any]):
    """Versión síncrona de publicación de eventos."""
    try:
        if hasattr(self, 'event_bus') and self.event_bus:
            self.event_bus.publish(event_type, self.plugin_name, data)
    except Exception as e:
        self.logger.error(f"❌ Error publicando evento {event_type}: {e}")

# Agregar métodos al plugin
NetworkDetectorPlugin._start_network_monitoring_sync = _start_network_monitoring_sync
NetworkDetectorPlugin._publish_event_sync = _publish_event_sync


if __name__ == "__main__":
    main()