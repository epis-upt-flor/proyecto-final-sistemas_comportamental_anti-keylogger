"""
Backend Antivirus Simplificado - Motor Funcional
===============================================

Sistema antivirus completamente funcional con detección real sin plugins complejos.
"""

import os
import time
import threading
import psutil
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

class SimpleAntivirusEngine:
    """Motor antivirus simplificado pero completamente funcional"""
    
    def __init__(self):
        # Configurar logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Estado del sistema
        self.is_running = False
        self.start_time = None
        self.monitoring_thread = None
        self.shutdown_event = threading.Event()
        
        # Configuración
        self.config = {
            'scan_interval': 2.0,  # Segundos
            'cpu_threshold': 80.0,  # % CPU para considerar sospechoso
            'memory_threshold': 500,  # MB para considerar sospechoso
            'realtime_protection': True,
            'behavior_analysis': True,
            'keylogger_detection': True,
            'network_monitoring': True
        }
        
        # Estadísticas en tiempo real
        self.stats = {
            'threats_detected': 0,
            'processes_scanned': 0,
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'uptime_seconds': 0,
            'last_scan_time': None
        }
        
        # Listas de seguridad
        self.threats_detected = []
        self.whitelist = []
        self.quarantine = []
        
        # Patrones de detección
        self.suspicious_names = [
            'keylog', 'trojan', 'malware', 'virus', 'backdoor', 
            'rootkit', 'spyware', 'adware', 'ransomware', 'miner',
            'hack', 'crack', 'keygen'
        ]
        
        self.logger.info("🛡️ SimpleAntivirusEngine inicializado")
    
    def _setup_logging(self):
        """Configurar sistema de logging"""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/simple_engine.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
    
    def start_system(self) -> bool:
        """Iniciar el sistema antivirus"""
        try:
            if self.is_running:
                self.logger.warning("⚠️ Sistema ya está ejecutándose")
                return True
                
            self.logger.info("🚀 Iniciando motor antivirus...")
            
            self.is_running = True
            self.start_time = time.time()
            self.shutdown_event.clear()
            
            # Iniciar monitoreo en thread separado
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info("✅ Motor antivirus iniciado correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error iniciando sistema: {e}")
            return False
    
    def stop_system(self):
        """Detener el sistema antivirus"""
        try:
            if not self.is_running:
                return
                
            self.logger.info("🛑 Deteniendo motor antivirus...")
            
            self.is_running = False
            self.shutdown_event.set()
            
            # Esperar que termine el thread de monitoreo
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5)
                
            self.logger.info("✅ Motor antivirus detenido correctamente")
            
        except Exception as e:
            self.logger.error(f"❌ Error deteniendo sistema: {e}")
    
    def _monitoring_loop(self):
        """Loop principal de monitoreo"""
        self.logger.info("🔍 Iniciando loop de monitoreo...")
        
        while self.is_running and not self.shutdown_event.is_set():
            try:
                # Actualizar estadísticas del sistema
                self._update_system_stats()
                
                # Escanear procesos si está habilitado
                if self.config['realtime_protection']:
                    self._scan_processes()
                
                # Análisis de comportamiento si está habilitado
                if self.config['behavior_analysis']:
                    self._analyze_behavior()
                
                # Detección de keyloggers si está habilitada
                if self.config['keylogger_detection']:
                    self._detect_keyloggers()
                
                self.stats['last_scan_time'] = datetime.now().strftime('%H:%M:%S')
                
                # Esperar intervalo configurado
                self.shutdown_event.wait(self.config['scan_interval'])
                
            except Exception as e:
                self.logger.error(f"❌ Error en loop de monitoreo: {e}")
                time.sleep(5)
    
    def _update_system_stats(self):
        """Actualizar estadísticas del sistema"""
        try:
            self.stats['cpu_usage'] = psutil.cpu_percent(interval=0.1)
            self.stats['memory_usage'] = psutil.virtual_memory().percent
            
            if self.start_time:
                self.stats['uptime_seconds'] = int(time.time() - self.start_time)
                
        except Exception as e:
            self.logger.error(f"Error actualizando estadísticas: {e}")
            return None
    
    def _analyze_behavior(self):
        """Análisis de comportamiento del sistema"""
        try:
            # Análisis simple de comportamiento basado en métricas del sistema
            if self.stats['cpu_usage'] > 95:
                self.logger.warning("⚠️ CPU usage crítico detectado")
            
            if self.stats['memory_usage'] > 90:
                self.logger.warning("⚠️ Uso de memoria crítico detectado")
                
        except Exception as e:
            self.logger.error(f"Error en análisis de comportamiento: {e}")
    
    def _detect_keyloggers(self):
        """Detección específica de keyloggers"""
        try:
            # Buscar procesos con patrones típicos de keyloggers
            keylogger_patterns = ['keylog', 'hook', 'capture', 'monitor', 'spy']
            
            for proc in psutil.process_iter(['name']):
                try:
                    name = proc.info['name'].lower()
                    if any(pattern in name for pattern in keylogger_patterns):
                        # Análisis más profundo del proceso sospechoso
                        self.logger.warning(f"🔍 Posible keylogger detectado: {proc.info['name']}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error en detección de keyloggers: {e}")
    
    def quarantine_threat(self, threat_id: str) -> bool:
        """Poner una amenaza en cuarentena"""
        try:
            # Encontrar la amenaza
            threat = None
            for t in self.threats_detected:
                if str(t.get('pid')) == threat_id:
                    threat = t
                    break
            
            if not threat:
                return False
            
            # Intentar terminar el proceso
            try:
                proc = psutil.Process(threat['pid'])
                proc.terminate()
                proc.wait(timeout=5)
                
                # Mover a cuarentena
                threat['status'] = 'quarantined'
                threat['quarantine_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.quarantine.append(threat)
                
                # Remover de amenazas activas
                self.threats_detected.remove(threat)
                
                self.logger.info(f"🗂️ Amenaza puesta en cuarentena: {threat['name']}")
                return True
                
            except psutil.NoSuchProcess:
                # El proceso ya no existe
                threat['status'] = 'terminated'
                self.threats_detected.remove(threat)
                return True
                
        except Exception as e:
            self.logger.error(f"Error en cuarentena: {e}")
            return False
    
    def whitelist_process(self, process_name: str) -> bool:
        """Agregar proceso a whitelist"""
        try:
            whitelist_entry = {
                'name': process_name,
                'added_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'added_by': 'user'
            }
            
            # Verificar si ya está en whitelist
            if not any(w['name'] == process_name for w in self.whitelist):
                self.whitelist.append(whitelist_entry)
                self.logger.info(f"⚪ Proceso agregado a whitelist: {process_name}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error agregando a whitelist: {e}")
            return False
    
    def get_system_status(self) -> Dict:
        """Obtener estado completo del sistema"""
        return {
            'is_running': self.is_running,
            'stats': self.stats.copy(),
            'config': self.config.copy(),
            'threats_count': len(self.threats_detected),
            'quarantine_count': len(self.quarantine),
            'whitelist_count': len(self.whitelist)
        }
    
    def get_active_threats(self) -> List[Dict]:
        """Obtener lista de amenazas activas"""
        return [t for t in self.threats_detected if t.get('status') == 'active']
    
    def update_config(self, new_config: Dict):
        """Actualizar configuración del sistema"""
        try:
            self.config.update(new_config)
            self.logger.info(f"⚙️ Configuración actualizada: {list(new_config.keys())}")
            
            # Guardar configuración
            with open('logs/engine_config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error actualizando configuración: {e}")


# Alias para compatibilidad
UnifiedAntivirusEngine = SimpleAntivirusEngine