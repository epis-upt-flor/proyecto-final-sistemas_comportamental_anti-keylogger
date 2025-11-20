# MDSD Template - Este archivo contiene placeholders que se reemplazan automáticamente
# Los errores de sintaxis son normales - este NO es código final sino una plantilla
# Cuando se genera un detector real, todos los {{placeholders}} se reemplazan por código válido

# Para evitar errores de linting, creamos versiones con valores por defecto:

"""
Template Base para Detectores - MDSD Simple
=============================================

Este template se llena automáticamente con variables
Los {{placeholders}} se reemplazan por código real durante la generación
"""

import logging
import time
from typing import Dict, List, Any, Optional
from core.interfaces import DetectorInterface
from core.base_plugin import BasePlugin

# Estos valores son placeholders - se reemplazan durante la generación
DETECTOR_NAME_PLACEHOLDER = "{{detector_name}}"
DETECTOR_CLASS_PLACEHOLDER = "{{detector_class_name}}"
DESCRIPTION_PLACEHOLDER = "{{detector_description}}"
PRIORITY_PLACEHOLDER = "{{priority}}"
THRESHOLD_PLACEHOLDER = "{{threshold}}"
TRIGGER_CHECKS_PLACEHOLDER = "{{trigger_checks}}"
TRIGGER_LOGIC_PLACEHOLDER = "{{trigger_logic}}"
RESPONSE_ACTIONS_PLACEHOLDER = "{{response_actions}}"
HELPER_METHODS_PLACEHOLDER = "{{helper_methods}}"

# Template del detector (se procesa por el generador MDSD)
DETECTOR_TEMPLATE = '''
"""
{description}

Generado automáticamente via MDSD Simple  
"""

import logging
import time
from typing import Dict, List, Any, Optional
from core.interfaces import DetectorInterface
from core.base_plugin import BasePlugin


class {class_name}DetectorPlugin(BasePlugin, DetectorInterface):
    """
    {description}
    
    Generado automáticamente via MDSD Simple
    """
    
    def __init__(self, plugin_name: str, plugin_path: str):
        super().__init__(plugin_name, plugin_path)
        self.name = "{detector_name}"
        self.description = "{description}"
        self.enabled = True
        self.priority = {priority}
        
        # Setup del logger específico
        self.setup_logging()
        self.logger.info("🚀 " + self.name + " detector creado")
    
    def detect_threats(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Interface requerida por DetectorInterface - Detecta amenazas en datos del sistema
        
        Args:
            system_data: Datos del sistema para analizar
            
        Returns:
            List[Dict]: Lista de amenazas detectadas
        """
        threats = []
        
        # Analizar procesos individuales si están disponibles
        processes = system_data.get('processes', [])
        if not processes:
            # Si no hay procesos específicos, tratar system_data como un proceso
            processes = [system_data]
            
        for process_data in processes:
            threat_result = self._detect_single_process(process_data)
            if threat_result.get('threat_detected', False):
                threats.append({{
                    "threat_type": "malware",
                    "severity": "high" if threat_result.get('threat_score', 0) > 0.8 else "medium",
                    "process_data": process_data,
                    "detection_result": threat_result,
                    "detector_name": self.name
                }})
                
        return threats
    
    def _detect_single_process(self, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detección principal para un proceso individual - {detector_name}
        
        Triggers configurados:
{trigger_checks}
        """
        
        detection_start = time.time()
        threat_score = 0.0
        
        try:
            # Evaluación de triggers
{trigger_logic}
            
            # Determinar si hay amenaza
            threat_detected = threat_score >= {threshold}
            
            # Actualizar estadísticas
            self._confidence_score = threat_score
            if hasattr(self, '_detection_stats'):
                self._detection_stats['total_detections'] += 1
                if threat_detected:
                    self._detection_stats['threats_detected'] += 1
                    self._detection_stats['last_detection'] = time.time()
            
            # Ejecutar respuestas si hay amenaza
            if threat_detected:
{response_actions}
            
            detection_time = time.time() - detection_start
            
            return {{
                "threat_detected": threat_detected,
                "threat_score": threat_score,
                "detection_time_ms": detection_time * 1000,
                "detector_name": self.name,
                "generated_by_mdsd": True
            }}
            
        except Exception as e:
            self.logger.error("❌ Error en " + self.name + ": " + str(e))
            return {{
                "threat_detected": False,
                "error": str(e),
                "detector_name": self.name
            }}

{helper_methods}

    # =================== MÉTODOS ABSTRACTOS DE BasePlugin ===================
    
    def initialize(self) -> bool:
        """Inicialización específica del detector MDSD"""
        try:
            self.logger.info(f"🔧 Inicializando " + self.name + "...")
            
            # Inicializar componentes específicos del detector
            self._confidence_score = 0.0
            self._detection_stats = {{
                "total_detections": 0,
                "threats_detected": 0,
                "false_positives": 0,
                "last_detection": None
            }}
            
            self.logger.info(f"✅ " + self.name + " inicializado correctamente")
            return True
        except Exception as e:
            self.logger.error("❌ Error inicializando " + self.name + ": " + str(e))
            return False
    
    def start(self) -> bool:
        """Inicio del detector"""
        try:
            self.logger.info(f"🚀 Iniciando " + self.name + "...")
            self.is_running = True
            return True
        except Exception as e:
            self.logger.error("❌ Error iniciando " + self.name + ": " + str(e))
            return False
    
    def stop(self) -> bool:
        """Parada del detector"""
        try:
            self.logger.info(f"🛑 Deteniendo " + self.name + "...")
            self.is_running = False
            return True
        except Exception as e:
            self.logger.error("❌ Error deteniendo " + self.name + ": " + str(e))
            return False

    # =================== MÉTODOS ABSTRACTOS DE DetectorInterface ===================
    
    def get_confidence_score(self) -> float:
        """Nivel de confianza de la última detección"""
        return getattr(self, '_confidence_score', 0.0)
    
    def update_signatures(self) -> bool:
        """Actualiza firmas/patrones - Para MDSD no aplica (generado automáticamente)"""
        self.logger.info(f"📋 " + self.name + ": Firmas MDSD siempre actualizadas")
        return True
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Estadísticas de detección del detector"""
        stats = getattr(self, '_detection_stats', {{}})
        stats.update({{
            "detector_name": self.name,
            "generated_by": "MDSD_Simple",
            "priority": {priority},
            "threshold": {threshold}
        }})
        return stats

    def get_plugin_info(self) -> Dict[str, Any]:
        """Información del plugin generado"""
        return {{
            "name": "{detector_name}",
            "description": "{description}",
            "generated_by": "MDSD_Simple",
            "version": "1.0.0",
            "priority": {priority},
            "enabled": True,
            "type": "detector",
            "interfaces": ["DetectorInterface", "BasePlugin"]
        }}


# Factory function para registro automático
def create_plugin():
    """Factory function requerida por el sistema de plugins"""
    plugin_name = "{detector_name}".lower().replace(" ", "_")
    plugin_path = "plugins/detectors/generated"
    return {class_name}DetectorPlugin(plugin_name, plugin_path)
'''
