"""
Rule Engine para Behavior Detector
==================================

Motor de reglas configurable para análisis heurístico de comportamientos.
Implementa Strategy Pattern y Chain of Responsibility para evaluación de reglas.
"""

import logging
import re
from typing import Dict, List, Any, Set, Optional, Tuple
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Niveles de riesgo"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(Enum):
    """Tipos de reglas"""
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    SYSTEM = "system"


class BaseRule(ABC):
    """
    Clase base para reglas de detección
    
    Implementa Strategy Pattern para diferentes tipos de análisis
    """
    
    def __init__(self, rule_id: str, name: str, risk_weight: float, rule_type: RuleType):
        self.rule_id = rule_id
        self.name = name
        self.risk_weight = risk_weight
        self.rule_type = rule_type
        self.enabled = True
        self.match_count = 0
        
    @abstractmethod
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Evalúa la regla contra los datos
        
        Returns:
            Tuple[bool, float, Dict]: (matched, risk_score, details)
        """
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de la regla"""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'type': self.rule_type.value,
            'enabled': self.enabled,
            'match_count': self.match_count,
            'risk_weight': self.risk_weight
        }


class ProcessNameRule(BaseRule):
    """Regla para patrones de nombres de proceso sospechosos"""
    
    def __init__(self, rule_id: str, patterns: List[str], risk_weight: float = 0.8):
        super().__init__(rule_id, "Process Name Pattern", risk_weight, RuleType.PROCESS)
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            process_name = data.get('process_info', {}).get('name', '')
            
            if not process_name:
                return False, 0.0, {}
            
            # Verificar patrones
            for pattern in self.patterns:
                if pattern.search(process_name):
                    self.match_count += 1
                    return True, self.risk_weight, {
                        'matched_process': process_name,
                        'matched_pattern': pattern.pattern,
                        'rule_type': 'process_name_pattern'
                    }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en ProcessNameRule: {e}")
            return False, 0.0, {}


class CommandLineRule(BaseRule):
    """Regla para líneas de comando sospechosas"""
    
    def __init__(self, rule_id: str, patterns: List[str], risk_weight: float = 0.9):
        super().__init__(rule_id, "Suspicious Command Line", risk_weight, RuleType.PROCESS)
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            cmdline = data.get('process_info', {}).get('cmdline', '')
            
            if not cmdline:
                return False, 0.0, {}
            
            # Verificar patrones en línea de comando
            for pattern in self.patterns:
                if pattern.search(cmdline):
                    self.match_count += 1
                    return True, self.risk_weight, {
                        'matched_cmdline': cmdline,
                        'matched_pattern': pattern.pattern,
                        'rule_type': 'suspicious_command_line'
                    }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en CommandLineRule: {e}")
            return False, 0.0, {}


class APICallRule(BaseRule):
    """Regla para APIs peligrosas utilizadas por keyloggers"""
    
    def __init__(self, rule_id: str, dangerous_apis: List[str], risk_weight: float = 0.9):
        super().__init__(rule_id, "Dangerous API Calls", risk_weight, RuleType.PROCESS)
        self.dangerous_apis = {api.lower() for api in dangerous_apis}
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            # Buscar datos en múltiples formatos para compatibilidad
            behaviors = data.get('behaviors', [])
            stealth_patterns = data.get('stealth_patterns', [])
            
            # APIs: buscar en ambos formatos (KeyloggerDetector y legacy)
            api_calls = data.get('api_calls', [])
            suspicious_apis = data.get('suspicious_apis', [])
            all_apis = list(api_calls) + list(suspicious_apis)
            
            # Verificar comportamientos conocidos
            if 'api_hooking' in behaviors or 'api_hooking' in stealth_patterns:
                self.match_count += 1
                return True, self.risk_weight, {
                    'detected_behavior': 'api_hooking',
                    'rule_type': 'dangerous_api_usage'
                }
            
            # Verificar llamadas API específicas (formato unificado)
            for api_call in all_apis:
                api_name = api_call.lower() if isinstance(api_call, str) else str(api_call).lower()
                if api_name in self.dangerous_apis:
                    self.match_count += 1
                    return True, self.risk_weight, {
                        'detected_api': api_name,
                        'rule_type': 'dangerous_api_call'
                    }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en APICallRule: {e}")
            return False, 0.0, {}


class NetworkBehaviorRule(BaseRule):
    """Regla para comportamientos de red sospechosos"""
    
    def __init__(self, rule_id: str, suspicious_patterns: List[str], risk_weight: float = 0.6):
        super().__init__(rule_id, "Network Behavior Pattern", risk_weight, RuleType.NETWORK)
        self.suspicious_patterns = suspicious_patterns
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            behaviors = data.get('behaviors', [])
            stealth_patterns = data.get('stealth_patterns', [])
            
            # Red: buscar en múltiples formatos para compatibilidad
            network_activity = data.get('network_activity', {})
            network_connections = data.get('network_connections', [])
            
            # Verificar patrones en comportamientos (formato unificado)
            all_patterns = list(behaviors) + list(stealth_patterns)
            for pattern in self.suspicious_patterns:
                if any(pattern in behavior_pattern for behavior_pattern in all_patterns):
                    self.match_count += 1
                    return True, self.risk_weight, {
                        'detected_pattern': pattern,
                        'rule_type': 'network_behavior'
                    }
            
            # Verificar actividad de red específica
            if network_activity:
                external_connections = network_activity.get('external_connections', 0)
                upload_ratio = network_activity.get('upload_ratio', 0.0)
                
                # Conexiones externas frecuentes + ratio de subida alto
                if external_connections > 5 and upload_ratio > 0.8:
                    self.match_count += 1
                    return True, self.risk_weight * 0.8, {
                        'external_connections': external_connections,
                        'upload_ratio': upload_ratio,
                        'rule_type': 'data_exfiltration_pattern'
                    }
            
            # Verificar conexiones específicas de keyloggers
            if network_connections and len(network_connections) > 0:
                self.match_count += 1
                return True, self.risk_weight * 0.6, {
                    'network_connections_count': len(network_connections),
                    'rule_type': 'keylogger_network_activity'
                }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en NetworkBehaviorRule: {e}")
            return False, 0.0, {}


class FileBehaviorRule(BaseRule):
    """Regla para accesos a archivos sospechosos"""
    
    def __init__(self, rule_id: str, file_patterns: List[str], risk_weight: float = 0.5):
        super().__init__(rule_id, "Suspicious File Access", risk_weight, RuleType.FILE)
        self.file_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in file_patterns]
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            behaviors = data.get('behaviors', [])
            stealth_patterns = data.get('stealth_patterns', [])
            
            # Archivos: buscar en múltiples formatos para compatibilidad
            file_accesses = data.get('file_accesses', [])
            file_operations = data.get('file_operations', [])
            created_files = data.get('created_files', [])
            all_files = list(file_accesses) + list(file_operations) + list(created_files)
            
            # Verificar comportamiento de acceso a credenciales
            if ('suspicious_file_access' in behaviors or 
                'suspicious_file_access' in stealth_patterns):
                self.match_count += 1
                return True, self.risk_weight, {
                    'detected_behavior': 'suspicious_file_access',
                    'rule_type': 'credential_file_access'
                }
            
            # Verificar patrones de archivos específicos (formato unificado)
            for file_path in all_files:
                file_str = str(file_path)  # Convertir a string por si es Path
                for pattern in self.file_patterns:
                    if pattern.search(file_str):
                        self.match_count += 1
                        return True, self.risk_weight, {
                            'suspicious_file': file_str,
                            'matched_pattern': pattern.pattern,
                            'rule_type': 'suspicious_file_pattern'
                        }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en FileBehaviorRule: {e}")
            return False, 0.0, {}


class SystemBehaviorRule(BaseRule):
    """Regla para modificaciones del sistema sospechosas"""
    
    def __init__(self, rule_id: str, risk_weight: float = 0.6):
        super().__init__(rule_id, "System Modification", risk_weight, RuleType.SYSTEM)
        
    def evaluate(self, data: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        try:
            behaviors = data.get('behaviors', [])
            system_changes = data.get('system_changes', {})
            
            # Verificar modificaciones de registro
            registry_changes = system_changes.get('registry_changes', [])
            startup_changes = system_changes.get('startup_changes', [])
            
            if registry_changes or 'registry_modification' in behaviors:
                self.match_count += 1
                return True, self.risk_weight, {
                    'registry_changes': len(registry_changes),
                    'rule_type': 'registry_modification'
                }
            
            if startup_changes or 'persistence_mechanism' in behaviors:
                self.match_count += 1
                return True, self.risk_weight * 1.2, {
                    'startup_changes': len(startup_changes),
                    'rule_type': 'persistence_mechanism'
                }
            
            return False, 0.0, {}
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error en SystemBehaviorRule: {e}")
            return False, 0.0, {}


class RuleEngine:
    """
    Motor de reglas para análisis heurístico
    
    Implementa Chain of Responsibility para evaluación de múltiples reglas
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa el motor de reglas
        
        Args:
            config: Configuración de detección con reglas y pesos
        """
        self.config = config
        self.detection_rules = config.get('detection_rules', {})
        self.risk_config = config.get('risk_scoring', {})
        
        # Configuración de riesgo
        self.weights = self.risk_config.get('weights', {})
        self.thresholds = self.risk_config.get('thresholds', {
            'low_risk': 0.3,
            'medium_risk': 0.5, 
            'high_risk': 0.7,
            'critical_risk': 0.9
        })
        
        # Reglas cargadas
        self.rules: List[BaseRule] = []
        
        # Estadísticas
        self.stats = {
            'rules_loaded': 0,
            'evaluations_performed': 0,
            'rules_matched': 0,
            'total_risk_calculated': 0.0,
            'avg_risk_score': 0.0
        }
        
        # Cargar reglas desde configuración
        self._load_rules()
        
        logger.info(f"[RULE_ENGINE] Inicializado con {len(self.rules)} reglas")
    
    def _load_rules(self):
        """Carga reglas desde configuración"""
        try:
            # Reglas de proceso
            process_rules = self.detection_rules.get('process_behavior', {})
            
            # Patrones de nombres de proceso
            keylogger_patterns = process_rules.get('keylogger_process_patterns', [])
            if keylogger_patterns:
                rule = ProcessNameRule(
                    'process_name_patterns',
                    keylogger_patterns,
                    self.weights.get('suspicious_process_name', 0.8)
                )
                self.rules.append(rule)
            
            # Patrones de línea de comando
            cmdline_patterns = process_rules.get('suspicious_command_lines', [])
            if cmdline_patterns:
                rule = CommandLineRule(
                    'cmdline_patterns',
                    cmdline_patterns, 
                    self.weights.get('suspicious_command_line', 0.9)
                )
                self.rules.append(rule)
            
            # APIs peligrosas
            dangerous_apis = process_rules.get('dangerous_apis', [])
            if dangerous_apis:
                rule = APICallRule(
                    'dangerous_apis',
                    dangerous_apis,
                    self.weights.get('api_hooking', 0.9)
                )
                self.rules.append(rule)
            
            # Reglas de red
            network_rules = self.detection_rules.get('network_behavior', {})
            network_patterns = (
                network_rules.get('data_exfiltration_patterns', []) +
                network_rules.get('command_control_patterns', [])
            )
            if network_patterns:
                rule = NetworkBehaviorRule(
                    'network_behavior',
                    network_patterns,
                    self.weights.get('external_communication', 0.4)
                )
                self.rules.append(rule)
            
            # Reglas de archivos
            file_rules = self.detection_rules.get('file_behavior', {})
            file_patterns = file_rules.get('keylogger_file_patterns', [])
            if file_patterns:
                rule = FileBehaviorRule(
                    'file_patterns',
                    file_patterns,
                    self.weights.get('credential_file_access', 0.5)
                )
                self.rules.append(rule)
            
            # Reglas de sistema
            system_rules = self.detection_rules.get('system_behavior', {})
            if system_rules:
                rule = SystemBehaviorRule(
                    'system_behavior',
                    self.weights.get('registry_modification', 0.6)
                )
                self.rules.append(rule)
            
            self.stats['rules_loaded'] = len(self.rules)
            logger.info(f"[RULE_ENGINE] Cargadas {len(self.rules)} reglas de detección")
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error cargando reglas: {e}")
    
    def evaluate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evalúa datos contra todas las reglas (Chain of Responsibility)
        
        Args:
            data: Datos a analizar
            
        Returns:
            Dict: Resultado del análisis con riesgo y detalles
        """
        self.stats['evaluations_performed'] += 1
        
        matched_rules = []
        total_risk = 0.0
        threat_indicators = []
        
        try:
            # Evaluar cada regla
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                matched, risk_score, details = rule.evaluate(data)
                
                if matched:
                    matched_rules.append({
                        'rule_id': rule.rule_id,
                        'rule_name': rule.name,
                        'risk_score': risk_score,
                        'details': details
                    })
                    
                    total_risk += risk_score
                    threat_indicators.append(details.get('rule_type', 'unknown'))
                    self.stats['rules_matched'] += 1
            
            # Calcular nivel de riesgo
            risk_level = self._calculate_risk_level(total_risk)
            
            # Actualizar estadísticas
            self.stats['total_risk_calculated'] += total_risk
            if self.stats['evaluations_performed'] > 0:
                self.stats['avg_risk_score'] = (
                    self.stats['total_risk_calculated'] / self.stats['evaluations_performed']
                )
            
            return {
                'risk_score': total_risk,
                'risk_level': risk_level.value,
                'matched_rules': matched_rules,
                'threat_indicators': threat_indicators,
                'rules_evaluated': len([r for r in self.rules if r.enabled]),
                'evaluation_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"[RULE_ENGINE] Error evaluando datos: {e}")
            return {
                'risk_score': 0.0,
                'risk_level': RiskLevel.LOW.value,
                'matched_rules': [],
                'threat_indicators': [],
                'error': str(e)
            }
    
    def _calculate_risk_level(self, risk_score: float) -> RiskLevel:
        """Calcula el nivel de riesgo basado en la puntuación"""
        if risk_score >= self.thresholds.get('critical_risk', 0.9):
            return RiskLevel.CRITICAL
        elif risk_score >= self.thresholds.get('high_risk', 0.7):
            return RiskLevel.HIGH
        elif risk_score >= self.thresholds.get('medium_risk', 0.5):
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def get_rule_stats(self) -> List[Dict[str, Any]]:
        """Obtiene estadísticas de todas las reglas"""
        return [rule.get_stats() for rule in self.rules]
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del motor"""
        return {
            **self.stats,
            'enabled_rules': len([r for r in self.rules if r.enabled]),
            'disabled_rules': len([r for r in self.rules if not r.enabled]),
            'rule_types': {
                'process': len([r for r in self.rules if r.rule_type == RuleType.PROCESS]),
                'network': len([r for r in self.rules if r.rule_type == RuleType.NETWORK]),
                'file': len([r for r in self.rules if r.rule_type == RuleType.FILE]),
                'system': len([r for r in self.rules if r.rule_type == RuleType.SYSTEM])
            }
        }
    
    def enable_rule(self, rule_id: str):
        """Habilita una regla específica"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                logger.info(f"[RULE_ENGINE] Regla habilitada: {rule_id}")
                return
        logger.warning(f"[RULE_ENGINE] Regla no encontrada: {rule_id}")
    
    def disable_rule(self, rule_id: str):
        """Deshabilita una regla específica"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                logger.info(f"[RULE_ENGINE] Regla deshabilitada: {rule_id}")
                return
        logger.warning(f"[RULE_ENGINE] Regla no encontrada: {rule_id}")
    
    def update_risk_thresholds(self, new_thresholds: Dict[str, float]):
        """Actualiza los umbrales de riesgo"""
        self.thresholds.update(new_thresholds)
        logger.info(f"[RULE_ENGINE] Umbrales actualizados: {self.thresholds}")


if __name__ == "__main__":
    # Test standalone del rule engine
    print("🧪 Testing Rule Engine...")
    
    test_config = {
        'detection_rules': {
            'process_behavior': {
                'keylogger_process_patterns': ['.*keylog.*', '.*stealer.*'],
                'suspicious_command_lines': ['.*hook.*keyboard.*'],
                'dangerous_apis': ['SetWindowsHookEx', 'GetAsyncKeyState']
            }
        },
        'risk_scoring': {
            'weights': {
                'suspicious_process_name': 0.8,
                'suspicious_command_line': 0.9,
                'api_hooking': 0.9
            },
            'thresholds': {
                'low_risk': 0.3,
                'medium_risk': 0.5,
                'high_risk': 0.7,
                'critical_risk': 0.9
            }
        }
    }
    
    engine = RuleEngine(test_config)
    
    # Test data
    test_data = {
        'process_info': {
            'name': 'keylogger.exe',
            'cmdline': 'keylogger.exe --hook-keyboard --stealth'
        },
        'behaviors': ['api_hooking'],
        'api_calls': ['SetWindowsHookEx']
    }
    
    result = engine.evaluate_data(test_data)
    
    print(f"✅ Análisis completado:")
    print(f"   Risk Score: {result['risk_score']}")
    print(f"   Risk Level: {result['risk_level']}")
    print(f"   Matched Rules: {len(result['matched_rules'])}")
    print(f"   Indicators: {result['threat_indicators']}")
    
    print(f"\n📊 Stats del motor: {engine.get_engine_stats()}")