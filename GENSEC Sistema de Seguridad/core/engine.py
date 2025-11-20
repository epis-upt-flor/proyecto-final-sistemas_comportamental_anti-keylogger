"""
Unified Antivirus Engine - Facade Pattern
=========================================

Motor principal que coordina todos los plugins del sistema.
Implementa Facade Pattern para simplificar la interfaz compleja.
"""

import logging
import signal
import sys
import time
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

from .plugin_manager import PluginManager
from .event_bus import event_bus, Event
from .plugin_registry import PluginRegistry

# Configurar logging principal
import os
# Asegurar que la carpeta de logs existe
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/antivirus.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class UnifiedAntivirusEngine:
    """
    Motor principal del Sistema Anti-Keylogger Unificado.
    
    Implementa Facade Pattern que simplifica:
    - Gestión de plugins
    - Comunicación entre componentes
    - Ciclo de vida del sistema
    - Configuración global
    
    Es el punto de entrada principal del sistema.
    """
    
    def __init__(self, config_path: str = "config/unified_config.toml"):
        self.config_path = config_path
        self.plugin_manager = PluginManager()
        self.is_running = False
        self.start_time = None
        
        # Estadísticas del sistema
        self.stats = {
            'threats_detected': 0,
            'scans_performed': 0,
            'false_positives': 0,
            'uptime_seconds': 0
        }
        
        # Thread para estadísticas
        self._stats_thread = None
        self._shutdown_event = threading.Event()
        
        # Inicializar componentes TDD
        self.memory_monitor = None
        self.consensus_engine = None
        
        # Configurar manejadores de señales para shutdown graceful (solo en main thread)
        try:
            if threading.current_thread() == threading.main_thread():
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
                logger.debug("✅ Manejadores de señales configurados correctamente")
            else:
                logger.debug("📟 Engine ejecutándose en hilo secundario (normal en UI)")
        except ValueError as e:
            logger.warning(f"⚠️ No se pudieron configurar señales: {e}")
        
        logger.info("🛡️ UnifiedAntivirusEngine inicializado")
    
    # =================== FACADE METHODS ===================
    def start_system(self, plugin_categories: List[str] = None) -> bool:
        """
        Inicia el sistema completo - Facade principal.
        
        Args:
            plugin_categories: Categorías de plugins a activar (None para todas)
            
        Returns:
            True si el inicio fue exitoso
        """
        try:
            logger.info("🚀 Iniciando Sistema Anti-Keylogger Unificado...")
            
            # 1. Descubrir y cargar plugins
            if not self.plugin_manager.discover_and_load_plugins():
                logger.error("❌ Falló el descubrimiento de plugins")
                return False
            
            # 2. Suscribir a eventos del sistema
            self._setup_system_event_handlers()
            
            # 3. Activar plugins por categoría
            if plugin_categories:
                for category in plugin_categories:
                    self.plugin_manager.activate_category(category)
            else:
                # Activar en orden específico para dependencias
                self._activate_plugins_in_order()
            
            # 4. Iniciar monitoreo de estadísticas
            self._start_stats_monitoring()
            
            # 5. Marcar como running
            self.is_running = True
            self.start_time = time.time()
            
            # 6. Publicar evento de inicio
            event_bus.publish(
                'system_started',
                {
                    'active_plugins': self.plugin_manager.get_active_plugins(),
                    'start_time': self.start_time
                },
                'UnifiedEngine'
            )
            
            logger.info("✅ Sistema iniciado exitosamente")
            logger.info(f"📊 Plugins activos: {len(self.plugin_manager.get_active_plugins())}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error iniciando sistema: {e}")
            return False
    
    def shutdown_system(self) -> bool:
        """
        Detiene el sistema de manera segura - Facade de shutdown.
        
        Returns:
            True si el shutdown fue exitoso
        """
        try:
            logger.info("🛑 Iniciando shutdown del sistema...")
            
            # 1. Marcar como no running
            self.is_running = False
            self._shutdown_event.set()
            
            # 2. Publicar evento de shutdown
            event_bus.publish(
                'system_shutdown_started',
                {'uptime_seconds': time.time() - self.start_time if self.start_time else 0},
                'UnifiedEngine'
            )
            
            # 3. Detener monitoreo de estadísticas
            if self._stats_thread and self._stats_thread.is_alive():
                self._stats_thread.join(timeout=5)
            
            # 4. Desactivar todos los plugins de forma agresiva
            logger.info("🛑 Forzando shutdown de plugins...")
            shutdown_success = self.plugin_manager.shutdown_all_plugins()
            if not shutdown_success:
                logger.warning("⚠️ Algunos plugins no se desactivaron correctamente, forzando terminación...")
                # Forzar terminación de threads de plugins
                self.plugin_manager.force_shutdown()
            
            # 5. Limpiar event bus
            event_bus.clear_history()
            
            logger.info("✅ Sistema detenido exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error en shutdown: {e}")
            return False
    
    def restart_system(self) -> bool:
        """Reinicia el sistema completo"""
        logger.info("🔄 Reiniciando sistema...")
        
        if not self.shutdown_system():
            return False
        
        time.sleep(2)  # Pausa entre shutdown y startup
        
        return self.start_system()
    
    # =================== PLUGIN CONTROL ===================
    def activate_plugin(self, plugin_name: str) -> bool:
        """Activa un plugin específico"""
        return self.plugin_manager.activate_plugin(plugin_name)
    
    def deactivate_plugin(self, plugin_name: str) -> bool:
        """Desactiva un plugin específico"""
        return self.plugin_manager.deactivate_plugin(plugin_name)
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Recarga un plugin (desactiva y activa)"""
        if self.plugin_manager.is_plugin_active(plugin_name):
            if not self.plugin_manager.deactivate_plugin(plugin_name):
                return False
        
        return self.plugin_manager.activate_plugin(plugin_name)
    
    def get_plugin_status(self, plugin_name: str) -> Dict[str, Any]:
        """Estado detallado de un plugin"""
        return {
            'name': plugin_name,
            'active': self.plugin_manager.is_plugin_active(plugin_name),
            'status': self.plugin_manager.get_plugin_status(plugin_name),
            'category': PluginRegistry().get_category(plugin_name),
            'info': PluginRegistry().get_plugin_info(plugin_name)
        }
    
    # =================== SYSTEM MONITORING ===================
    def get_system_status(self) -> Dict[str, Any]:
        """Estado completo del sistema"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            'system_running': self.is_running,
            'uptime_seconds': uptime,
            'uptime_formatted': self._format_uptime(uptime),
            'active_plugins': self.plugin_manager.get_active_plugins(),
            'plugin_stats': self.plugin_manager.get_manager_statistics(),
            'threat_stats': self.stats.copy(),
            'event_bus_stats': event_bus.get_statistics()
        }
    
    def get_recent_events(self, event_type: str = None, limit: int = 10) -> List[Dict]:
        """Eventos recientes del sistema"""
        return event_bus.get_recent_events(event_type, limit)
    
    def perform_system_scan(self) -> Dict[str, Any]:
        """
        Ejecuta un escaneo completo del sistema.
        Coordina todos los detectores activos.
        """
        logger.info("🔍 Iniciando escaneo completo del sistema...")
        
        scan_results = {
            'scan_id': f"scan_{int(time.time())}",
            'start_time': time.time(),
            'detectors_used': [],
            'threats_found': [],
            'scan_status': 'running'
        }
        
        try:
            # Obtener detectores activos
            detectors = self.plugin_manager.get_plugins_by_category('detectors')
            
            if not detectors:
                scan_results['scan_status'] = 'no_detectors'
                logger.warning("⚠️ No hay detectores activos")
                return scan_results
            
            # Publicar inicio de escaneo
            event_bus.publish(
                'scan_started',
                scan_results.copy(),
                'UnifiedEngine'
            )
            
            # Ejecutar cada detector (esto es simplificado)
            for detector in detectors:
                detector_name = detector.get_name()
                scan_results['detectors_used'].append(detector_name)
                
                # En implementación real, cada detector haría su escaneo
                # Por ahora solo simulamos
                logger.info(f"🔍 Escaneando con {detector_name}...")
            
            # Completar escaneo
            scan_results['end_time'] = time.time()
            scan_results['duration'] = scan_results['end_time'] - scan_results['start_time']
            scan_results['scan_status'] = 'completed'
            
            self.stats['scans_performed'] += 1
            
            # Publicar finalización
            event_bus.publish(
                'scan_completed',
                scan_results.copy(),
                'UnifiedEngine'
            )
            
            logger.info(f"✅ Escaneo completado en {scan_results['duration']:.2f}s")
            return scan_results
            
        except Exception as e:
            logger.error(f"❌ Error en escaneo: {e}")
            scan_results['scan_status'] = 'error'
            scan_results['error'] = str(e)
            return scan_results
    
    # =================== INTERNAL METHODS ===================
    def _activate_plugins_in_order(self):
        """Activa plugins en orden específico para manejar dependencias"""
        activation_order = ['detectors', 'monitors', 'handlers', 'interfaces']
        
        for category in activation_order:
            success = self.plugin_manager.activate_category(category)
            if success:
                logger.info(f"✅ Categoría '{category}' activada")
            else:
                logger.warning(f"⚠️ Problemas activando categoría '{category}'")
    
    def _setup_system_event_handlers(self):
        """Configura manejadores de eventos del sistema"""
        
        def on_threat_detected(event: Event):
            """Maneja detección de amenazas a nivel sistema"""
            self.stats['threats_detected'] += 1
            threat_data = event.data
            
            logger.warning(f"🚨 AMENAZA DETECTADA: {threat_data.get('threat_type', 'unknown')}")
            
            # Registrar en logs de seguridad
            security_logger = logging.getLogger('security')
            security_logger.warning(f"Threat detected: {threat_data}")
        
        def on_plugin_error(event: Event):
            """Maneja errores de plugins"""
            plugin_name = event.data.get('plugin_name', 'unknown')
            error = event.data.get('error', 'unknown error')
            
            logger.error(f"❌ Error en plugin {plugin_name}: {error}")
        
        # Suscribir a eventos importantes
        event_bus.subscribe('threat_detected', on_threat_detected, 'UnifiedEngine')
        event_bus.subscribe('plugin_error', on_plugin_error, 'UnifiedEngine')
    
    def _start_stats_monitoring(self):
        """Inicia hilo de monitoreo de estadísticas"""
        def stats_monitor():
            while not self._shutdown_event.is_set():
                try:
                    if self.is_running and self.start_time:
                        self.stats['uptime_seconds'] = time.time() - self.start_time
                    
                    time.sleep(30)  # Actualizar cada 30 segundos
                except Exception as e:
                    logger.error(f"Error en monitoreo de estadísticas: {e}")
        
        self._stats_thread = threading.Thread(
            target=stats_monitor,
            name="StatsMonitor",
            daemon=True
        )
        self._stats_thread.start()
    
    def _format_uptime(self, seconds: float) -> str:
        """Formatea uptime en formato legible"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    def _signal_handler(self, signum, frame):
        """Maneja señales del sistema para shutdown graceful"""
        logger.info(f"🛑 Señal recibida ({signum}), iniciando shutdown...")
        self.shutdown_system()
        sys.exit(0)
    
    # =================== CONTEXT MANAGER ===================
    def __enter__(self):
        """Permite usar el engine como context manager"""
        self.start_system()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Shutdown automático al salir del context"""
        self.shutdown_system()

    # =================== MEMORY MONITORING METHODS ===================
    def analyze_memory_usage(self, process_name: str, memory_mb: float, threshold_mb: float = 1024) -> Dict[str, Any]:
        """
        Analizar uso de memoria de un proceso
        
        Args:
            process_name: Nombre del proceso
            memory_mb: Uso actual de memoria en MB
            threshold_mb: Umbral de memoria sospechosa en MB
            
        Returns:
            Análisis de memoria con risk_level y suspicion_score
        """
        if self.memory_monitor is None:
            self.memory_monitor = MemoryMonitor()
        
        return self.memory_monitor.analyze_memory_usage(process_name, memory_mb, threshold_mb)
    
    def combine_threat_results(self, detector_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Combinar resultados de múltiples detectores usando consenso
        
        Args:
            detector_results: Resultados de cada detector
            
        Returns:
            Resultado consensuado con final_risk_level y confidence
        """
        if self.consensus_engine is None:
            self.consensus_engine = ConsensusEngine()
        
        return self.consensus_engine.combine_threat_results(detector_results)
    
    def get_memory_monitor(self):
        """Obtener referencia al monitor de memoria"""
        if self.memory_monitor is None:
            self.memory_monitor = MemoryMonitor()
        return self.memory_monitor
    
    def get_consensus_engine(self):
        """Obtener referencia al motor de consenso"""
        if self.consensus_engine is None:
            self.consensus_engine = ConsensusEngine()
        return self.consensus_engine


class MemoryMonitor:
    """Monitor de uso de memoria para procesos sospechosos"""
    
    def __init__(self):
        self.memory_threshold = 1024  # MB
        self.suspicious_processes = {}
        
    def analyze_memory_usage(self, process_name: str, memory_mb: float, threshold_mb: float = 1024) -> Dict[str, Any]:
        """
        Analizar uso de memoria de un proceso
        
        Args:
            process_name: Nombre del proceso
            memory_mb: Uso actual de memoria en MB
            threshold_mb: Umbral de sospecha en MB
            
        Returns:
            Diccionario con análisis de memoria
        """
        # Calcular ratio de uso respecto al umbral
        memory_ratio = memory_mb / threshold_mb
        
        # Determinar nivel de riesgo
        if memory_ratio >= 2.0:
            risk_level = "HIGH"
            suspicion_score = min(0.9, 0.8 + (memory_ratio - 2.0) * 0.1)
        elif memory_ratio >= 1.5:
            risk_level = "MEDIUM"
            suspicion_score = min(0.7, 0.3 + (memory_ratio - 1.5) * 0.4)
        elif memory_ratio >= 1.0:
            risk_level = "LOW"  
            suspicion_score = min(0.5, 0.1 + (memory_ratio - 1.0) * 0.4)
        else:
            risk_level = "NORMAL"
            suspicion_score = min(0.3, memory_ratio * 0.3)
        
        # Registrar proceso sospechoso si es necesario
        if risk_level in ["HIGH", "MEDIUM"]:
            self.suspicious_processes[process_name] = {
                'memory_mb': memory_mb,
                'ratio': memory_ratio,
                'risk_level': risk_level,
                'timestamp': time.time()
            }
        
        return {
            'process_name': process_name,
            'memory_usage_mb': memory_mb,
            'threshold_mb': threshold_mb,
            'memory_ratio': memory_ratio,
            'risk_level': risk_level,
            'suspicion_score': suspicion_score,
            'recommendations': self._get_memory_recommendations(risk_level, memory_ratio)
        }
    
    def _get_memory_recommendations(self, risk_level: str, memory_ratio: float) -> List[str]:
        """Generar recomendaciones basadas en uso de memoria"""
        recommendations = []
        
        if risk_level == "HIGH":
            recommendations.extend([
                "Proceso consumiendo memoria excesiva - investigar inmediatamente",
                "Verificar si es un proceso legítimo o posible malware",
                "Considerar terminación del proceso si es sospechoso"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "Proceso con uso elevado de memoria - monitorear",
                "Verificar comportamiento del proceso"
            ])
        elif risk_level == "LOW":
            recommendations.append("Uso de memoria ligeramente elevado - observar")
        
        return recommendations


class ConsensusEngine:
    """Motor de consenso para combinar resultados de múltiples detectores"""
    
    def __init__(self):
        self.detector_weights = {
            'ml_detector': 0.4,
            'behavior_detector': 0.3,
            'network_detector': 0.2,
            'keylogger_detector': 0.1
        }
        self.risk_values = {
            'HIGH': 1.0,
            'MEDIUM': 0.6,
            'LOW': 0.3,
            'NORMAL': 0.1
        }
    
    def combine_threat_results(self, detector_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Combinar resultados de múltiples detectores
        
        Args:
            detector_results: Resultados por detector con risk_level, confidence, score
            
        Returns:
            Resultado consensuado
        """
        if not detector_results:
            return {
                'final_risk_level': 'NORMAL',
                'confidence': 0.0,
                'consensus_score': 0.0,
                'detector_count': 0
            }
        
        total_weighted_score = 0.0
        total_weight = 0.0
        total_confidence = 0.0
        detector_count = len(detector_results)
        
        # Combinar resultados ponderados
        for detector_name, result in detector_results.items():
            weight = self.detector_weights.get(detector_name, 0.1)
            risk_level = result.get('risk_level', 'NORMAL')
            confidence = result.get('confidence', 0.5)
            score = result.get('score', self.risk_values.get(risk_level, 0.1))
            
            # Calcular contribución ponderada
            weighted_score = score * confidence * weight
            total_weighted_score += weighted_score
            total_weight += weight
            total_confidence += confidence
        
        # Calcular consenso final
        if total_weight > 0:
            consensus_score = total_weighted_score / total_weight
            avg_confidence = total_confidence / detector_count
        else:
            consensus_score = 0.0
            avg_confidence = 0.0
        
        # Determinar nivel de riesgo final
        if consensus_score >= 0.6:
            final_risk_level = "HIGH"
        elif consensus_score >= 0.4:
            final_risk_level = "MEDIUM"  
        elif consensus_score >= 0.2:
            final_risk_level = "LOW"
        else:
            final_risk_level = "NORMAL"
        
        return {
            'final_risk_level': final_risk_level,
            'confidence': avg_confidence,
            'consensus_score': consensus_score,
            'detector_count': detector_count,
            'individual_results': detector_results,
            'weights_used': self.detector_weights
        }


# =================== LAUNCHER FUNCTION ===================
def main():
    """Función principal de lanzamiento"""
    engine = UnifiedAntivirusEngine()
    
    try:
        if engine.start_system():
            logger.info("Sistema iniciado. Presiona Ctrl+C para detener.")
            
            # Mantener el sistema corriendo
            while engine.is_running:
                time.sleep(1)
        else:
            logger.error("❌ No se pudo iniciar el sistema")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Interrupción del usuario detectada")
    finally:
        engine.shutdown_system()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())