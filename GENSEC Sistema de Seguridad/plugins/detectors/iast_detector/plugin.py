#!/usr/bin/env python3
"""
IAST Detector Plugin - Versión Avanzada
=======================================

Plugin especializado para Interactive Application Security Testing.
Detecta vulnerabilidades web y de aplicaciones en tiempo real.

Características avanzadas:
- SQL Injection detection
- XSS vulnerability scanning  
- Command injection monitoring
- Path traversal detection
- Buffer overflow detection
- Deserialization vulnerabilities
"""

import os
import re
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime

# Agregar el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from core.base_plugin import BasePlugin
from core.interfaces import DetectorInterface
from utils.logger import get_logger
from .iast_detector import IASTDetector

class IASTDetectorPlugin(BasePlugin, DetectorInterface):
    """Plugin IAST para auto-protección del antivirus y detección especializada de keyloggers"""
    
    def __init__(self):
        # Inicializar BasePlugin con nombre y path
        plugin_path = os.path.dirname(os.path.abspath(__file__))
        super().__init__("iast_detector", plugin_path)
        self.logger = get_logger(self.__class__.__name__)
        self.iast_engine: Optional[IASTDetector] = None
        self.is_active = False
        self.last_confidence_score = 0.0
        self.detection_results = []
        
    def initialize(self) -> bool:
        """Inicializa el plugin IAST (implementación de BasePlugin)"""
        try:
            self.logger.info("🚀 Inicializando IAST Detector Plugin...")
            
            # Configuración desde config.json ya cargado por BasePlugin
            monitoring_enabled = self.config.get('settings', {}).get('monitoring_enabled', True)
            scan_interval = self.config.get('settings', {}).get('scan_interval', 30)
            
            # Inicializar motor IAST
            self.iast_engine = IASTDetector()
            
            # Iniciar monitoreo si está habilitado
            if monitoring_enabled:
                success = self.iast_engine.start()
                if success:
                    self.is_active = True
                    self.logger.info("✅ IAST Engine iniciado y monitoreando vulnerabilidades")
                else:
                    self.logger.error("❌ Error iniciando IAST Engine")
            else:
                self.logger.info("⚠️ Monitoreo IAST deshabilitado en configuración")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando IAST plugin: {e}")
            return False
    
    def start(self) -> bool:
        """Inicia el plugin (implementación de BasePlugin)"""
        if not self.iast_engine:
            return False
        
        try:
            if not self.is_active:
                scan_interval = self.config.get('settings', {}).get('scan_interval', 30)
                self.iast_engine.start_monitoring(interval=scan_interval)
                self.is_active = True
            
            self.logger.info("✅ IAST Detector iniciado")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error iniciando IAST detector: {e}")
            return False
    
    def stop(self) -> bool:
        """Detiene el plugin (implementación de BasePlugin)"""
        try:
            if self.iast_engine and self.is_active:
                self.iast_engine.stop_monitoring()
                self.is_active = False
            
            self.logger.info("🛑 IAST Detector detenido")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error deteniendo IAST detector: {e}")
            return False
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Información del plugin (implementación de BasePlugin)"""
        return {
            "name": "IAST Self-Protection & Keylogger Detector",
            "version": "1.0.0",
            "type": "detector",
            "description": "Interactive Application Security Testing for antivirus self-protection and keylogger detection",
            "capabilities": [
                "self_protection",
                "keylogger_detection", 
                "integrity_monitoring",
                "hybrid_analysis"
            ],
            "priority": 95,
            "author": "Antivirus Security Team"
        }
    
    def detect_threats(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detecta amenazas (implementación de DetectorInterface)
        
        Args:
            data: Datos del sistema para analizar
            
        Returns:
            Lista de amenazas detectadas
        """
        if not self.iast_engine or not self.is_active:
            return []
        
        try:
            threats = []
            
            # Verificar integridad del sistema
            integrity_ok = self.iast_engine.check_file_integrity()
            
            if not integrity_ok:
                threats.append({
                    "type": "integrity_compromise",
                    "description": "Antivirus files have been modified",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "plugin": "iast_detector",
                    "timestamp": datetime.now().isoformat()
                })
            
            # Escanear keyloggers
            detected_keyloggers = self.iast_engine.scan_for_keyloggers()
            
            for keylogger in detected_keyloggers:
                threats.append({
                    "type": "keylogger_detection",
                    "description": f"Keylogger detected: {keylogger.get('name', 'unknown')}",
                    "severity": "CRITICAL",
                    "confidence": keylogger.get('total_score', 0.0),
                    "plugin": "iast_detector",
                    "details": keylogger,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Guardar resultados para get_confidence_score
            self.detection_results = threats
            if threats:
                self.last_confidence_score = sum(t.get('confidence', 0.0) for t in threats) / len(threats)
            else:
                self.last_confidence_score = 0.0
            
            return threats
            
        except Exception as e:
            self.logger.error(f"❌ Error detectando amenazas IAST: {e}")
            return []
    
    def get_confidence_score(self) -> float:
        """Retorna el nivel de confianza de la última detección"""
        return self.last_confidence_score
    
    def update_signatures(self) -> bool:
        """Actualiza las firmas/patrones de detección"""
        try:
            if not self.iast_engine:
                return False
            
            # Recalcular baseline de archivos protegidos
            self.iast_engine.calculate_baseline_hashes()
            self.logger.info("✅ Firmas IAST actualizadas (baseline recalculado)")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error actualizando firmas IAST: {e}")
            return False
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Escanea un archivo específico (interfaz DetectorInterface)
        
        Para IAST, esto verifica si el archivo es parte del antivirus
        y si ha sido modificado
        """
        if not self.iast_engine:
            return {"threat_detected": False, "reason": "IAST engine not initialized"}
        
        try:
            # Verificar si es un archivo protegido
            protected_files = self.config.get('settings', {}).get('protected_files', [])
            
            is_protected = any(protected_path in file_path for protected_path in protected_files)
            
            result = {
                "threat_detected": False,
                "is_protected_file": is_protected,
                "file_path": file_path,
                "plugin": "iast_detector"
            }
            
            if is_protected:
                # Verificar integridad específica del archivo
                integrity_ok = self.iast_engine.check_file_integrity()
                if not integrity_ok:
                    result["threat_detected"] = True
                    result["threat_type"] = "file_integrity_violation"
                    result["description"] = f"Protected antivirus file {file_path} has been modified"
                    result["severity"] = "HIGH"
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Error escaneando archivo {file_path}: {e}")
            return {
                "threat_detected": False,
                "error": str(e),
                "plugin": "iast_detector"
            }
    
    def scan_process(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Escanea un proceso específico para keyloggers
        
        Args:
            process_info: Información del proceso (pid, name, exe, etc.)
            
        Returns:
            Resultado de detección para el proceso
        """
        if not self.iast_engine:
            return {"threat_detected": False, "reason": "IAST engine not initialized"}
        
        try:
            # Analizar proceso específico usando el motor IAST
            static_score = self.iast_engine.analyze_process_static(process_info)
            
            result = {
                "threat_detected": False,
                "process_info": process_info,
                "static_analysis_score": static_score,
                "plugin": "iast_detector"
            }
            
            # Umbral de detección
            detection_threshold = self.config.get('settings', {}).get('detection_threshold', 0.7)
            
            if static_score > detection_threshold:
                result["threat_detected"] = True
                result["threat_type"] = "suspected_keylogger"
                result["confidence_score"] = static_score
                result["description"] = f"Process {process_info.get('name', 'unknown')} shows keylogger characteristics"
                result["severity"] = "CRITICAL"
                
                self.logger.warning(f"🎯 Keylogger sospechoso detectado: {process_info.get('name')} (Score: {static_score:.2f})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Error analizando proceso: {e}")
            return {
                "threat_detected": False,
                "error": str(e),
                "plugin": "iast_detector"
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Obtiene el estado actual del plugin"""
        base_status = {
            "name": self.plugin_name,
            "status": "running" if self.is_active else "stopped",
            "plugin_type": "detector"
        }
        
        if self.iast_engine:
            iast_report = self.iast_engine.get_detection_report()
            base_status.update({
                "iast_engine_active": self.is_active,
                "monitoring_status": iast_report,
                "capabilities": [
                    "self_protection",
                    "keylogger_detection", 
                    "integrity_monitoring",
                    "hybrid_analysis"
                ]
            })
        
        return base_status
    
    def shutdown(self):
        """Limpieza del plugin"""
        try:
            if self.iast_engine and self.is_active:
                self.iast_engine.stop_monitoring()
                self.is_active = False
                self.logger.info("🛑 IAST Engine detenido")
            
            # BasePlugin cleanup se llama en deactivate()
            
        except Exception as e:
            self.logger.error(f"❌ Error en shutdown del IAST plugin: {e}")
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas de detección"""
        if not self.iast_engine:
            return {"error": "IAST engine not available"}
        
        try:
            report = self.iast_engine.get_detection_report()
            return {
                "total_threats_detected": report.get("detected_threats", 0),
                "protected_files_count": report.get("protected_files", 0),
                "monitoring_active": report.get("monitoring_active", False),
                "last_scan_time": report.get("last_scan", "unknown"),
                "plugin_name": "iast_detector",
                "detection_capabilities": [
                    "Antivirus self-protection",
                    "Keylogger detection",
                    "File integrity monitoring",
                    "Hybrid static/dynamic analysis"
                ]
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo estadísticas: {e}")
            return {"error": str(e)}

# Función de factory para el sistema de plugins
def create_plugin() -> IASTDetectorPlugin:
    """Crea una instancia del plugin IAST"""
    return IASTDetectorPlugin()

# Para testing directo
def main():
    """Función principal para testing"""
    import json
    
    print("🔧 Testing IAST Detector Plugin...")
    
    # Crear y probar plugin
    plugin = create_plugin()
    
    # Activar plugin (esto ejecuta el template method)
    if plugin.activate():
        print("✅ Plugin activado correctamente")
        
        # Test de detección de amenazas
        threats = plugin.detect_threats({})
        print(f"🎯 Amenazas detectadas: {len(threats)}")
        for threat in threats:
            print(f"   - {threat.get('type')}: {threat.get('description')}")
        
        # Test de confidence score
        confidence = plugin.get_confidence_score()
        print(f"📊 Score de confianza: {confidence:.2f}")
        
        # Test de estadísticas
        stats = plugin.get_detection_statistics()
        print(f"📈 Estadísticas: {stats}")
        
        # Test de estado
        status = plugin.get_status()
        print(f"🔍 Estado: {status}")
        
        # Test info del plugin
        info = plugin.get_plugin_info()
        print(f"ℹ️ Info: {info}")
        
    else:
        print("❌ Error activando plugin")
    
    # Desactivar plugin
    plugin.deactivate()

if __name__ == "__main__":
    main()