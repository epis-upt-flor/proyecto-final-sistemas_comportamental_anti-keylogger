"""
Behavior Engine para Detector de Comportamientos
================================================

Motor principal de análisis heurístico que coordina reglas y whitelist.
Implementa múltiples patrones para análisis integral de comportamientos.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Importar componentes del behavior detector
from .rule_engine import RuleEngine, RiskLevel
from .whitelist_manager import WhitelistManager

logger = logging.getLogger(__name__)


class BehaviorEngine:
    """
    Motor principal de análisis de comportamiento
    
    Patrones implementados:
    - Strategy Pattern: Diferentes estrategias de análisis según tipo de datos
    - Observer Pattern: Monitoreo continuo de comportamientos
    - Command Pattern: Comandos de análisis ejecutables
    - Template Method: Proceso estándar de análisis
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa el motor de comportamiento
        
        Args:
            config: Configuración completa del behavior detector
        """
        self.config = config
        self.behavior_config = config.get('behavior_config', {})
        
        # Componentes principales
        self.rule_engine = RuleEngine(config)
        self.whitelist_manager = WhitelistManager(config)
        
        # Configuración de análisis
        self.risk_threshold = self.behavior_config.get('risk_threshold', 0.7)
        self.enable_advanced_analysis = self.behavior_config.get('enable_advanced_analysis', True)
        self.analysis_timeout = self.behavior_config.get('analysis_timeout_ms', 10000) / 1000.0
        
        # Performance y concurrencia
        self.performance_config = config.get('performance', {})
        self.max_concurrent = self.performance_config.get('max_concurrent_analyses', 3)
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent)
        
        # Cache de análisis recientes
        self.analysis_cache = {}
        self.cache_ttl = self.performance_config.get('analysis_cache_ttl', 60)  # segundos
        
        # Timeline de comportamientos para correlación
        self.behavior_timeline = defaultdict(deque)
        self.timeline_window = timedelta(
            minutes=config.get('advanced_analysis', {}).get('correlation_window_minutes', 10)
        )
        
        # Estadísticas
        self.stats = {
            'total_analyses': 0,
            'threats_detected': 0,
            'whitelisted_skipped': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_analysis_time': 0.0,
            'concurrent_analyses': 0,
            'advanced_analyses': 0,
            'behavior_correlations': 0
        }
        
        self._lock = threading.Lock()
        
        logger.info(f"[BEHAVIOR_ENGINE] Inicializado (threshold: {self.risk_threshold}, advanced: {self.enable_advanced_analysis})")
    
    def analyze(self, monitor_name: str, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Método principal de análisis (Template Method Pattern)
        
        Args:
            monitor_name: Nombre del monitor que proporciona los datos
            data: Lista de datos a analizar
            
        Returns:
            List[Dict]: Lista de amenazas detectadas
        """
        threats = []
        
        try:
            start_time = datetime.now()
            self.stats['total_analyses'] += 1
            
            # Paso 1: Filtrar por whitelist
            filtered_data = self._filter_whitelisted_data(data)
            
            if not filtered_data:
                logger.debug(f"[BEHAVIOR_ENGINE] Todos los datos filtrados por whitelist para {monitor_name}")
                return threats
            
            # Paso 2: Análisis según tipo de monitor (Strategy Pattern)
            if monitor_name == 'process':
                threats.extend(self._analyze_process_behavior(filtered_data))
            elif monitor_name == 'network':
                threats.extend(self._analyze_network_behavior(filtered_data))
            elif monitor_name == 'filesystem':
                threats.extend(self._analyze_file_behavior(filtered_data))
            elif monitor_name == 'system':
                threats.extend(self._analyze_system_behavior(filtered_data))
            else:
                logger.warning(f"[BEHAVIOR_ENGINE] Monitor desconocido: {monitor_name}")
            
            # Paso 3: Análisis avanzado si está habilitado
            if self.enable_advanced_analysis and threats:
                threats = self._perform_advanced_analysis(threats, filtered_data)
            
            # Paso 4: Actualizar estadísticas
            analysis_time = (datetime.now() - start_time).total_seconds()
            self._update_stats(len(threats), analysis_time)
            
            logger.debug(f"[BEHAVIOR_ENGINE] {monitor_name}: {len(threats)} amenazas detectadas en {analysis_time:.3f}s")
            
        except Exception as e:
            logger.error(f"[BEHAVIOR_ENGINE] Error en análisis de {monitor_name}: {e}")
        
        return threats
    
    def _filter_whitelisted_data(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filtra datos usando whitelist"""
        if not self.whitelist_manager.enabled:
            return data
        
        filtered_data = []
        
        for item in data:
            process_info = item.get('process_info', {})
            process_name = process_info.get('name', '')
            process_path = process_info.get('exe', '')
            
            if not self.whitelist_manager.is_whitelisted(process_name, process_path):
                filtered_data.append(item)
            else:
                self.stats['whitelisted_skipped'] += 1
        
        return filtered_data
    
    def _analyze_process_behavior(self, process_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analiza comportamiento de procesos"""
        threats = []
        
        for proc_data in process_data:
            try:
                # Verificar cache primero
                cache_key = self._generate_cache_key('process', proc_data)
                cached_result = self._get_cached_analysis(cache_key)
                
                if cached_result:
                    self.stats['cache_hits'] += 1
                    threats.extend(cached_result)
                    continue
                
                self.stats['cache_misses'] += 1
                
                # Análisis con rule engine
                analysis_result = self.rule_engine.evaluate_data(proc_data)
                
                # Crear amenaza si supera el threshold
                if analysis_result['risk_score'] >= self.risk_threshold:
                    threat = self._create_threat_from_analysis(
                        'process', proc_data, analysis_result
                    )
                    threats.append(threat)
                    
                    # Agregar al timeline para correlación
                    self._add_to_timeline(proc_data, analysis_result)
                
                # Guardar en cache
                self._cache_analysis(cache_key, threats[-1:] if threats else [])
                
            except Exception as e:
                logger.error(f"[BEHAVIOR_ENGINE] Error analizando proceso: {e}")
        
        return threats
    
    def _analyze_network_behavior(self, network_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analiza comportamiento de red"""
        threats = []
        
        # Agrupar por proceso para análisis correlacionado
        process_network_map = defaultdict(list)
        
        for net_data in network_data:
            process_info = net_data.get('process_info', {})
            process_name = process_info.get('name', 'unknown')
            process_network_map[process_name].append(net_data)
        
        # Analizar cada proceso por separado
        for process_name, proc_net_data in process_network_map.items():
            try:
                # Agregar datos agregados de red al análisis
                aggregated_data = self._aggregate_network_data(proc_net_data)
                
                # Análisis con rule engine
                analysis_result = self.rule_engine.evaluate_data(aggregated_data)
                
                if analysis_result['risk_score'] >= self.risk_threshold:
                    threat = self._create_threat_from_analysis(
                        'network', aggregated_data, analysis_result
                    )
                    threats.append(threat)
                    
                    # Timeline para correlación
                    self._add_to_timeline(aggregated_data, analysis_result)
                
            except Exception as e:
                logger.error(f"[BEHAVIOR_ENGINE] Error analizando red para {process_name}: {e}")
        
        return threats
    
    def _analyze_file_behavior(self, file_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analiza comportamiento de archivos"""
        threats = []
        
        for file_item in file_data:
            try:
                # Análisis con rule engine
                analysis_result = self.rule_engine.evaluate_data(file_item)
                
                if analysis_result['risk_score'] >= self.risk_threshold:
                    threat = self._create_threat_from_analysis(
                        'file', file_item, analysis_result
                    )
                    threats.append(threat)
                    
                    # Timeline
                    self._add_to_timeline(file_item, analysis_result)
                
            except Exception as e:
                logger.error(f"[BEHAVIOR_ENGINE] Error analizando archivo: {e}")
        
        return threats
    
    def _analyze_system_behavior(self, system_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analiza comportamiento del sistema"""
        threats = []
        
        for sys_data in system_data:
            try:
                # Análisis con rule engine
                analysis_result = self.rule_engine.evaluate_data(sys_data)
                
                if analysis_result['risk_score'] >= self.risk_threshold:
                    threat = self._create_threat_from_analysis(
                        'system', sys_data, analysis_result
                    )
                    threats.append(threat)
                    
                    # Timeline
                    self._add_to_timeline(sys_data, analysis_result)
                
            except Exception as e:
                logger.error(f"[BEHAVIOR_ENGINE] Error analizando sistema: {e}")
        
        return threats
    
    def _perform_advanced_analysis(self, threats: List[Dict[str, Any]], data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Realiza análisis avanzado con correlación temporal"""
        try:
            self.stats['advanced_analyses'] += 1
            
            enhanced_threats = []
            
            for threat in threats:
                # Buscar correlaciones en el timeline
                correlations = self._find_correlations(threat)
                
                if correlations:
                    self.stats['behavior_correlations'] += len(correlations)
                    
                    # Aumentar severity si hay correlaciones
                    enhanced_threat = threat.copy()
                    enhanced_threat['correlations'] = correlations
                    enhanced_threat['correlation_count'] = len(correlations)
                    
                    # Recalcular severity basado en correlaciones
                    original_confidence = enhanced_threat.get('confidence', 0.0)
                    correlation_boost = min(0.3, len(correlations) * 0.1)
                    enhanced_threat['confidence'] = min(1.0, original_confidence + correlation_boost)
                    
                    # Actualizar severity
                    if enhanced_threat['confidence'] > 0.9:
                        enhanced_threat['severity'] = 'critical'
                    elif enhanced_threat['confidence'] > 0.7:
                        enhanced_threat['severity'] = 'high'
                    
                    enhanced_threats.append(enhanced_threat)
                else:
                    enhanced_threats.append(threat)
            
            return enhanced_threats
            
        except Exception as e:
            logger.error(f"[BEHAVIOR_ENGINE] Error en análisis avanzado: {e}")
            return threats
    
    def _aggregate_network_data(self, net_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Agrega datos de red por proceso"""
        if not net_data_list:
            return {}
        
        # Usar el primer elemento como base
        aggregated = net_data_list[0].copy()
        
        # Agregar estadísticas de red
        total_connections = len(net_data_list)
        external_connections = sum(1 for item in net_data_list if item.get('external', False))
        total_upload = sum(item.get('bytes_uploaded', 0) for item in net_data_list)
        total_download = sum(item.get('bytes_downloaded', 0) for item in net_data_list)
        
        upload_ratio = total_upload / max(total_upload + total_download, 1)
        
        aggregated['network_activity'] = {
            'total_connections': total_connections,
            'external_connections': external_connections,
            'total_upload': total_upload,
            'total_download': total_download,
            'upload_ratio': upload_ratio
        }
        
        # Agregar comportamientos detectados
        behaviors = set()
        for item in net_data_list:
            behaviors.update(item.get('behaviors', []))
        
        # Detectar patrones específicos
        if external_connections > 5:
            behaviors.add('frequent_external_connections')
        
        if upload_ratio > 0.8 and total_upload > 1024:  # > 1KB uploaded with high ratio
            behaviors.add('data_exfiltration_pattern')
        
        aggregated['behaviors'] = list(behaviors)
        
        return aggregated
    
    def _create_threat_from_analysis(self, analysis_type: str, data: Dict[str, Any], analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Crea objeto threat desde resultado de análisis"""
        process_info = data.get('process_info', {})
        
        threat = {
            'id': f"behavior_threat_{datetime.now().timestamp()}_{analysis_type}",
            'type': 'keylogger',
            'source': 'behavior_detector',
            'analysis_type': analysis_type,
            'severity': self._calculate_severity(analysis_result['risk_score']),
            'confidence': min(1.0, analysis_result['risk_score']),
            'risk_score': analysis_result['risk_score'],
            'risk_level': analysis_result['risk_level'],
            'timestamp': datetime.now().isoformat(),
            'process_info': {
                'name': process_info.get('name', 'unknown'),
                'pid': process_info.get('pid'),
                'exe': process_info.get('exe'),
                'cmdline': process_info.get('cmdline')
            },
            'threat_indicators': analysis_result['threat_indicators'],
            'matched_rules': analysis_result['matched_rules'],
            'details': {
                'analysis_engine': 'behavior_heuristic',
                'rules_evaluated': analysis_result.get('rules_evaluated', 0),
                'raw_data_sample': self._sanitize_data_for_logging(data)
            }
        }
        
        # Agregar detalles específicos según tipo
        if analysis_type == 'network':
            network_activity = data.get('network_activity', {})
            threat['network_details'] = {
                'connections': network_activity.get('total_connections', 0),
                'external_connections': network_activity.get('external_connections', 0),
                'upload_ratio': network_activity.get('upload_ratio', 0.0)
            }
        
        return threat
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calcula severity basado en risk score"""
        if risk_score >= 0.9:
            return 'critical'
        elif risk_score >= 0.7:
            return 'high' 
        elif risk_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_cache_key(self, analysis_type: str, data: Dict[str, Any]) -> str:
        """Genera clave de cache para análisis"""
        process_info = data.get('process_info', {})
        key_data = f"{analysis_type}_{process_info.get('name', '')}_{process_info.get('pid', '')}"
        return str(hash(key_data))
    
    def _get_cached_analysis(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Obtiene resultado de análisis desde cache"""
        if cache_key not in self.analysis_cache:
            return None
        
        cached_entry = self.analysis_cache[cache_key]
        cache_time = cached_entry['timestamp']
        
        # Verificar TTL
        if (datetime.now() - cache_time).total_seconds() > self.cache_ttl:
            del self.analysis_cache[cache_key]
            return None
        
        return cached_entry['result']
    
    def _cache_analysis(self, cache_key: str, result: List[Dict[str, Any]]):
        """Guarda resultado en cache"""
        # Limitar tamaño del cache
        if len(self.analysis_cache) > 1000:
            # Remover entradas más antiguas
            oldest_key = min(self.analysis_cache.keys(), 
                           key=lambda k: self.analysis_cache[k]['timestamp'])
            del self.analysis_cache[oldest_key]
        
        self.analysis_cache[cache_key] = {
            'result': result,
            'timestamp': datetime.now()
        }
    
    def _add_to_timeline(self, data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Agrega evento al timeline para correlación"""
        try:
            process_name = data.get('process_info', {}).get('name', 'unknown')
            
            timeline_entry = {
                'timestamp': datetime.now(),
                'risk_score': analysis_result['risk_score'],
                'indicators': analysis_result['threat_indicators'],
                'matched_rules': [rule['rule_id'] for rule in analysis_result['matched_rules']]
            }
            
            # Agregar a timeline del proceso
            self.behavior_timeline[process_name].append(timeline_entry)
            
            # Limpiar entradas antiguas
            cutoff_time = datetime.now() - self.timeline_window
            while (self.behavior_timeline[process_name] and 
                   self.behavior_timeline[process_name][0]['timestamp'] < cutoff_time):
                self.behavior_timeline[process_name].popleft()
                
        except Exception as e:
            logger.error(f"[BEHAVIOR_ENGINE] Error agregando al timeline: {e}")
    
    def _find_correlations(self, threat: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Busca correlaciones en el timeline"""
        correlations = []
        
        try:
            process_name = threat.get('process_info', {}).get('name', 'unknown')
            threat_indicators = set(threat.get('threat_indicators', []))
            
            # Buscar en timeline del mismo proceso
            if process_name in self.behavior_timeline:
                for entry in self.behavior_timeline[process_name]:
                    entry_indicators = set(entry['indicators'])
                    
                    # Buscar indicadores relacionados
                    common_indicators = threat_indicators.intersection(entry_indicators)
                    
                    if common_indicators and entry['risk_score'] > 0.5:
                        correlations.append({
                            'timestamp': entry['timestamp'].isoformat(),
                            'risk_score': entry['risk_score'],
                            'common_indicators': list(common_indicators),
                            'correlation_type': 'temporal_behavior'
                        })
            
            # Buscar correlaciones entre procesos (comportamientos similares)
            for other_process, timeline in self.behavior_timeline.items():
                if other_process == process_name:
                    continue
                
                for entry in timeline:
                    entry_indicators = set(entry['indicators'])
                    common_indicators = threat_indicators.intersection(entry_indicators)
                    
                    if len(common_indicators) >= 2:  # Al menos 2 indicadores comunes
                        correlations.append({
                            'process': other_process,
                            'timestamp': entry['timestamp'].isoformat(),
                            'risk_score': entry['risk_score'],
                            'common_indicators': list(common_indicators),
                            'correlation_type': 'cross_process_behavior'
                        })
                        
        except Exception as e:
            logger.error(f"[BEHAVIOR_ENGINE] Error buscando correlaciones: {e}")
        
        return correlations[:5]  # Limitar a 5 correlaciones
    
    def _sanitize_data_for_logging(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitiza datos para logging (remueve información sensible)"""
        sanitized = {}
        
        # Solo incluir campos seguros
        safe_fields = ['process_info', 'behaviors', 'network_activity']
        
        for field in safe_fields:
            if field in data:
                sanitized[field] = data[field]
        
        return sanitized
    
    def _update_stats(self, threats_count: int, analysis_time: float):
        """Actualiza estadísticas del motor"""
        with self._lock:
            self.stats['threats_detected'] += threats_count
            
            # Media móvil del tiempo de análisis
            if self.stats['avg_analysis_time'] == 0:
                self.stats['avg_analysis_time'] = analysis_time
            else:
                alpha = 0.1
                self.stats['avg_analysis_time'] = (
                    alpha * analysis_time + (1 - alpha) * self.stats['avg_analysis_time']
                )
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas completas del motor"""
        engine_stats = {
            **self.stats,
            'rule_engine': self.rule_engine.get_engine_stats(),
            'whitelist': self.whitelist_manager.get_stats(),
            'cache_size': len(self.analysis_cache),
            'timeline_processes': len(self.behavior_timeline),
            'timeline_entries': sum(len(timeline) for timeline in self.behavior_timeline.values())
        }
        
        return engine_stats
    
    def update_risk_threshold(self, new_threshold: float):
        """Actualiza el threshold de riesgo"""
        if 0.0 <= new_threshold <= 1.0:
            self.risk_threshold = new_threshold
            logger.info(f"[BEHAVIOR_ENGINE] Threshold actualizado a {new_threshold}")
    
    def clear_cache(self):
        """Limpia cache de análisis"""
        self.analysis_cache.clear()
        logger.info("[BEHAVIOR_ENGINE] Cache limpiado")
    
    def clear_timeline(self):
        """Limpia timeline de comportamientos"""
        self.behavior_timeline.clear()
        logger.info("[BEHAVIOR_ENGINE] Timeline limpiado")
    
    def shutdown(self):
        """Cierra el motor limpiamente"""
        try:
            self.executor.shutdown(wait=True)
            self.clear_cache()
            logger.info("[BEHAVIOR_ENGINE] Motor cerrado correctamente")
        except Exception as e:
            logger.error(f"[BEHAVIOR_ENGINE] Error cerrando motor: {e}")


if __name__ == "__main__":
    # Test standalone del behavior engine
    print("🧪 Testing Behavior Engine...")
    
    test_config = {
        'behavior_config': {
            'risk_threshold': 0.7,
            'enable_advanced_analysis': True
        },
        'detection_rules': {
            'process_behavior': {
                'keylogger_process_patterns': ['.*keylog.*', '.*stealer.*'],
                'suspicious_command_lines': ['.*hook.*keyboard.*'],
                'dangerous_apis': ['SetWindowsHookEx']
            }
        },
        'risk_scoring': {
            'weights': {
                'suspicious_process_name': 0.8,
                'suspicious_command_line': 0.9
            },
            'thresholds': {
                'high_risk': 0.7
            }
        },
        'whitelist': {
            'enabled': False  # Deshabilitar para test
        }
    }
    
    engine = BehaviorEngine(test_config)
    
    # Test data
    test_process_data = [{
        'process_info': {
            'name': 'keylogger.exe',
            'pid': 1234,
            'cmdline': 'keylogger.exe --hook-keyboard'
        },
        'behaviors': ['api_hooking']
    }]
    
    threats = engine.analyze('process', test_process_data)
    
    print(f"✅ Análisis completado:")
    print(f"   Amenazas detectadas: {len(threats)}")
    if threats:
        threat = threats[0]
        print(f"   Tipo: {threat['type']}")
        print(f"   Severity: {threat['severity']}")
        print(f"   Confidence: {threat['confidence']:.2f}")
        print(f"   Risk Score: {threat['risk_score']:.2f}")
    
    print(f"\n📊 Stats: {engine.get_stats()}")