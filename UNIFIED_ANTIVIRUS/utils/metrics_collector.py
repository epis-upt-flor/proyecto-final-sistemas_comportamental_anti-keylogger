"""
Sistema de Métricas en Tiempo Real
=================================

Recopila métricas reales del sistema y del antivirus para mostrar en la UI.
Proporciona datos reales de CPU, memoria, red, amenazas detectadas, etc.
"""

import psutil
import time
import threading
import logging
from typing import Dict, List, Any, Optional
from collections import deque
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class SystemMetrics:
    """Recolector de métricas del sistema en tiempo real"""
    
    def __init__(self, max_samples: int = 60):
        self.max_samples = max_samples
        self.is_collecting = False
        self.collection_thread = None
        
        # Historial de métricas
        self.cpu_history = deque(maxlen=max_samples)
        self.memory_history = deque(maxlen=max_samples)
        self.network_history = deque(maxlen=max_samples)
        self.disk_history = deque(maxlen=max_samples)
        
        # Métricas de antivirus
        self.threats_detected = deque(maxlen=max_samples)
        self.scans_performed = deque(maxlen=max_samples)
        self.plugins_status = {}
        
        # Cache de procesos para optimización
        self._process_cache = {}
        self._last_process_update = 0
        
        logger.info("SystemMetrics inicializado con {} muestras máximo", max_samples)
    
    def start_collection(self, interval: float = 1.0):
        """Inicia la recolección de métricas"""
        if self.is_collecting:
            return
            
        self.is_collecting = True
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            args=(interval,),
            daemon=True,
            name="MetricsCollector"
        )
        self.collection_thread.start()
        logger.info("✅ Recolección de métricas iniciada (intervalo: {}s)", interval)
    
    def stop_collection(self):
        """Detiene la recolección de métricas"""
        self.is_collecting = False
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=2.0)
        logger.info("🛑 Recolección de métricas detenida")
    
    def _collection_loop(self, interval: float):
        """Loop principal de recolección"""
        while self.is_collecting:
            try:
                timestamp = time.time()
                
                # Recopilar métricas del sistema
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory_info = psutil.virtual_memory()
                disk_info = psutil.disk_usage('/')
                network_info = self._get_network_metrics()
                
                # Agregar al historial
                self.cpu_history.append({
                    'timestamp': timestamp,
                    'value': cpu_percent
                })
                
                self.memory_history.append({
                    'timestamp': timestamp,
                    'used': memory_info.used,
                    'total': memory_info.total,
                    'percent': memory_info.percent
                })
                
                self.network_history.append({
                    'timestamp': timestamp,
                    'bytes_sent': network_info.get('bytes_sent', 0),
                    'bytes_recv': network_info.get('bytes_recv', 0),
                    'packets_sent': network_info.get('packets_sent', 0),
                    'packets_recv': network_info.get('packets_recv', 0)
                })
                
                self.disk_history.append({
                    'timestamp': timestamp,
                    'used': disk_info.used,
                    'total': disk_info.total,
                    'percent': (disk_info.used / disk_info.total) * 100
                })
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error recolectando métricas: {e}")
                time.sleep(interval)
    
    def _get_network_metrics(self) -> Dict[str, int]:
        """Obtiene métricas de red"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except Exception as e:
            logger.debug(f"Error obteniendo métricas de red: {e}")
            return {}
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Obtiene las métricas actuales"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = self._get_network_metrics()
            
            return {
                'cpu': {
                    'percent': cpu_percent,
                    'cores': psutil.cpu_count(),
                    'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
                },
                'memory': {
                    'total': memory.total,
                    'used': memory.used,
                    'available': memory.available,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': network,
                'processes': len(psutil.pids()),
                'timestamp': time.time()
            }
        except Exception as e:
            logger.error(f"Error obteniendo métricas actuales: {e}")
            return {}
    
    def get_history_data(self, metric_type: str, last_n: int = None) -> List[Dict[str, Any]]:
        """Obtiene historial de métricas"""
        history_map = {
            'cpu': self.cpu_history,
            'memory': self.memory_history,
            'network': self.network_history,
            'disk': self.disk_history,
            'threats': self.threats_detected,
            'scans': self.scans_performed
        }
        
        if metric_type not in history_map:
            return []
        
        history = history_map[metric_type]
        if last_n:
            return list(history)[-last_n:]
        return list(history)
    
    def record_threat_detection(self, threat_data: Dict[str, Any]):
        """Registra una detección de amenaza"""
        self.threats_detected.append({
            'timestamp': time.time(),
            'threat_type': threat_data.get('type', 'unknown'),
            'severity': threat_data.get('severity', 'medium'),
            'source': threat_data.get('source', 'unknown'),
            'details': threat_data
        })
        logger.debug(f"Amenaza registrada: {threat_data.get('type', 'unknown')}")
    
    def record_scan_completion(self, scan_data: Dict[str, Any]):
        """Registra la finalización de un escaneo"""
        self.scans_performed.append({
            'timestamp': time.time(),
            'scan_type': scan_data.get('type', 'unknown'),
            'duration': scan_data.get('duration', 0),
            'files_scanned': scan_data.get('files_scanned', 0),
            'threats_found': scan_data.get('threats_found', 0)
        })
        logger.debug(f"Escaneo registrado: {scan_data.get('type', 'unknown')}")
    
    def update_plugin_status(self, plugin_name: str, status: Dict[str, Any]):
        """Actualiza el estado de un plugin"""
        self.plugins_status[plugin_name] = {
            'timestamp': time.time(),
            'status': status.get('status', 'unknown'),
            'active': status.get('active', False),
            'detections': status.get('detections', 0),
            'last_activity': status.get('last_activity', time.time())
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Obtiene un resumen de rendimiento"""
        try:
            current = self.get_current_metrics()
            
            # Calcular promedios de los últimos 10 minutos
            recent_cpu = self.get_history_data('cpu', 10)
            recent_memory = self.get_history_data('memory', 10)
            recent_threats = self.get_history_data('threats', 100)
            
            avg_cpu = sum(item['value'] for item in recent_cpu) / len(recent_cpu) if recent_cpu else 0
            avg_memory = sum(item['percent'] for item in recent_memory) / len(recent_memory) if recent_memory else 0
            
            return {
                'current_cpu': current.get('cpu', {}).get('percent', 0),
                'current_memory': current.get('memory', {}).get('percent', 0),
                'avg_cpu_10min': avg_cpu,
                'avg_memory_10min': avg_memory,
                'threats_last_hour': len(recent_threats),
                'plugins_active': len([p for p in self.plugins_status.values() if p.get('active', False)]),
                'system_health': self._calculate_system_health(current)
            }
        except Exception as e:
            logger.error(f"Error calculando resumen de rendimiento: {e}")
            return {}
    
    def _calculate_system_health(self, metrics: Dict[str, Any]) -> str:
        """Calcula el estado general del sistema"""
        try:
            cpu = metrics.get('cpu', {}).get('percent', 0)
            memory = metrics.get('memory', {}).get('percent', 0)
            disk = metrics.get('disk', {}).get('percent', 0)
            
            if cpu > 90 or memory > 90 or disk > 95:
                return 'critical'
            elif cpu > 70 or memory > 80 or disk > 85:
                return 'warning'
            elif cpu > 50 or memory > 60 or disk > 70:
                return 'good'
            else:
                return 'excellent'
        except Exception:
            return 'unknown'

class AntivirusMetrics:
    """Métricas específicas del antivirus"""
    
    def __init__(self, system_metrics: SystemMetrics):
        self.system_metrics = system_metrics
        self.logger = logging.getLogger(f"{__name__}.AntivirusMetrics")
        
        # Contadores de actividad
        self.total_threats_detected = 0
        self.total_scans_performed = 0
        self.total_files_quarantined = 0
        
        # Estado de plugins
        self.plugin_stats = {}
        
        self.logger.info("AntivirusMetrics inicializado")
    
    def process_engine_log_entry(self, log_entry: str):
        """Procesa una entrada de log del engine para extraer métricas"""
        try:
            if "🚨" in log_entry and ("detectado" in log_entry or "detected" in log_entry):
                # Amenaza detectada
                threat_type = self._extract_threat_type(log_entry)
                severity = self._extract_severity(log_entry)
                
                threat_data = {
                    'type': threat_type,
                    'severity': severity,
                    'source': 'engine_log',
                    'raw_log': log_entry
                }
                
                self.system_metrics.record_threat_detection(threat_data)
                self.total_threats_detected += 1
                
            elif "Scan completed" in log_entry or "Escaneo completado" in log_entry:
                # Escaneo completado
                scan_data = self._extract_scan_data(log_entry)
                self.system_metrics.record_scan_completion(scan_data)
                self.total_scans_performed += 1
                
        except Exception as e:
            self.logger.debug(f"Error procesando entrada de log: {e}")
    
    def _extract_threat_type(self, log_entry: str) -> str:
        """Extrae el tipo de amenaza del log"""
        threat_types = ['keylogger', 'malware', 'virus', 'trojan', 'adware', 'spyware']
        
        log_lower = log_entry.lower()
        for threat_type in threat_types:
            if threat_type in log_lower:
                return threat_type
                
        return 'unknown'
    
    def _extract_severity(self, log_entry: str) -> str:
        """Extrae la severidad de la amenaza"""
        if "CRITICAL" in log_entry or "CRÍTICO" in log_entry:
            return 'critical'
        elif "HIGH" in log_entry or "ALTO" in log_entry:
            return 'high'
        elif "MEDIUM" in log_entry or "MEDIO" in log_entry:
            return 'medium'
        else:
            return 'low'
    
    def _extract_scan_data(self, log_entry: str) -> Dict[str, Any]:
        """Extrae datos del escaneo del log"""
        return {
            'type': 'system_scan',
            'duration': 0,  # Podría extraerse del log si está disponible
            'files_scanned': 0,
            'threats_found': 0
        }
    
    def get_antivirus_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del antivirus"""
        return {
            'total_threats_detected': self.total_threats_detected,
            'total_scans_performed': self.total_scans_performed,
            'total_files_quarantined': self.total_files_quarantined,
            'plugins_status': self.system_metrics.plugins_status,
            'recent_threats': self.system_metrics.get_history_data('threats', 10)
        }

# Instancia global para el sistema de métricas
_metrics_instance = None

def get_metrics_system() -> SystemMetrics:
    """Obtiene la instancia global del sistema de métricas"""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = SystemMetrics()
    return _metrics_instance

def initialize_metrics(engine=None):
    """Inicializa el sistema de métricas"""
    metrics = get_metrics_system()
    metrics.start_collection()
    
    # Si hay un engine, crear métricas de antivirus
    if engine:
        antivirus_metrics = AntivirusMetrics(metrics)
        return metrics, antivirus_metrics
    
    return metrics, None