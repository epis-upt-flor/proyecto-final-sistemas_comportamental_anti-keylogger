"""
Consensus Engine - Sistema de Consenso para Múltiples Detectores
================================================================

Motor que combina resultados de múltiples detectores usando técnicas
de ensemble machine learning para mejorar la precisión global.

Implementa patrones Strategy y Factory para diferentes algoritmos de consenso.
Refactorizado siguiendo principios SOLID y Clean Code.
"""

import logging
from typing import Dict, List, Any, Optional, Protocol
from statistics import mean, median
from collections import Counter
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod

try:
    import numpy as np
except ImportError:
    np = None

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Niveles de riesgo estandardizados"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"  
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConsensusMethod(Enum):
    """Métodos disponibles de consenso"""
    WEIGHTED = "weighted_consensus"
    MAJORITY = "majority_vote"
    ENSEMBLE = "ensemble_ml"
    CONFLICT_RESOLUTION = "conflict_resolution"


@dataclass
class DetectorResult:
    """Resultado estructurado de un detector"""
    name: str
    risk_level: str
    confidence: float
    score: float
    metadata: Dict[str, Any] = None


@dataclass
class ConsensusResult:
    """Resultado del consenso de detectores"""
    final_risk_level: str
    consensus_score: float
    confidence: float
    detectors_count: int
    method: str
    individual_results: List[DetectorResult] = None


class ConsensusStrategy(Protocol):
    """Protocolo para estrategias de consenso"""
    
    def calculate(self, results: List[DetectorResult], 
                 weights: Dict[str, float]) -> ConsensusResult:
        """Calcula consenso usando esta estrategia"""
        ...


class WeightedConsensusStrategy:
    """Implementa estrategia de consenso ponderado"""
    
    @staticmethod
    def calculate(results: List[DetectorResult], 
                 weights: Dict[str, float]) -> ConsensusResult:
        """Calcula consenso usando pesos por detector"""
        
        # Mapeo de niveles de riesgo a valores numéricos
        risk_values_map = {
            RiskLevel.LOW.value: 1,
            RiskLevel.MEDIUM.value: 2, 
            RiskLevel.HIGH.value: 3
        }
        level_names = {1: RiskLevel.LOW.value, 2: RiskLevel.MEDIUM.value, 3: RiskLevel.HIGH.value}
        
        scores = []
        confidences = []
        risk_values = []
        total_weight = 0
        
        for result in results:
            weight = weights.get(result.name, 0.2)
            risk_value = risk_values_map.get(result.risk_level, 1)
            
            scores.append(result.score * weight)
            confidences.append(result.confidence * weight)
            risk_values.append(risk_value * weight)
            total_weight += weight
        
        # Normalizar por peso total
        final_score = sum(scores) / total_weight if total_weight > 0 else 0
        final_confidence = sum(confidences) / total_weight if total_weight > 0 else 0
        final_risk_value = sum(risk_values) / total_weight if total_weight > 0 else 1
        
        final_risk_level = level_names[round(final_risk_value)]
        
        return ConsensusResult(
            final_risk_level=final_risk_level,
            consensus_score=final_score,
            confidence=final_confidence,
            detectors_count=len(results),
            method=ConsensusMethod.WEIGHTED.value,
            individual_results=results
        )


class ConsensusEngine:
    """
    Motor de consenso refactorizado que combina resultados de múltiples detectores.
    
    Usa patrón Strategy para diferentes algoritmos de consenso.
    Implementa principios SOLID para extensibilidad.
    """
    
    # Constantes de clase
    DEFAULT_MIN_DETECTORS = 2
    DEFAULT_CONFIDENCE_THRESHOLD = 0.6
    
    def __init__(self, default_weights: Optional[Dict[str, float]] = None):
        """
        Inicializa el motor de consenso
        
        Args:
            default_weights: Pesos por defecto para cada detector
        """
        self._default_weights = default_weights or self._get_default_weights()
        self._strategies = {
            ConsensusMethod.WEIGHTED: WeightedConsensusStrategy()
        }
        
        # Mantener compatibilidad con métodos antiguos
        self.default_weights = self._default_weights
        self.risk_levels = {
            "LOW": 1,
            "MEDIUM": 2, 
            "HIGH": 3
        }
        self.level_names = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
        
        logger.info("ConsensusEngine inicializado con estrategias disponibles")
    
    def _get_default_weights(self) -> Dict[str, float]:
        """Obtiene pesos por defecto para detectores"""
        return {
            "ml_detector": 0.3,
            "behavior_detector": 0.25,
            "network_detector": 0.25,
            "api_detector": 0.2
        }
        
    def combine_detectors(self, detector_results: Dict[str, Dict[str, Any]], 
                         min_detectors: int = DEFAULT_MIN_DETECTORS,
                         method: ConsensusMethod = ConsensusMethod.WEIGHTED) -> Dict[str, Any]:
        """
        Combina resultados de múltiples detectores usando estrategia especificada
        
        Args:
            detector_results: Diccionario con resultados de cada detector
            min_detectors: Número mínimo de detectores requeridos
            method: Método de consenso a usar
            
        Returns:
            Resultado del consenso con nivel de riesgo final
        """
        self._validate_inputs(detector_results, min_detectors)
        
        # Convertir datos de entrada a formato estructurado
        structured_results = self._convert_to_structured_results(detector_results)
        
        # Aplicar estrategia de consenso
        strategy = self._strategies.get(method)
        if not strategy:
            raise ValueError(f"Método de consenso '{method}' no soportado")
        
        consensus_result = strategy.calculate(structured_results, self._default_weights)
        
        # Convertir a formato compatible con tests existentes
        return self._result_to_dict(consensus_result)
    
    def _validate_inputs(self, detector_results: Dict[str, Dict[str, Any]], 
                        min_detectors: int) -> None:
        """Valida las entradas del método principal"""
        if not detector_results:
            raise ValueError("No se proporcionaron resultados de detectores")
            
        if len(detector_results) < min_detectors:
            raise ValueError(f"Se requieren al menos {min_detectors} detectores, "
                           f"recibidos: {len(detector_results)}")
    
    def _convert_to_structured_results(self, 
                                     detector_results: Dict[str, Dict[str, Any]]) -> List[DetectorResult]:
        """Convierte datos de entrada a formato estructurado"""
        structured_results = []
        
        for detector_name, result in detector_results.items():
            structured_result = DetectorResult(
                name=detector_name,
                risk_level=result.get("risk_level", RiskLevel.LOW.value),
                confidence=result.get("confidence", 0.5),
                score=result.get("score", 0.5),
                metadata=result.get("metadata", {})
            )
            structured_results.append(structured_result)
        
        return structured_results
    
    def _result_to_dict(self, result: ConsensusResult) -> Dict[str, Any]:
        """Convierte resultado estructurado a diccionario para compatibilidad"""
        return {
            "final_risk_level": result.final_risk_level,
            "consensus_score": result.consensus_score,
            "confidence": result.confidence,
            "detectors_count": result.detectors_count,
            "method": result.method
        }
        confidences = []
        risk_values = []
        total_weight = 0
        
        for detector_name, result in detector_results.items():
            # Obtener peso del detector
            weight = self.default_weights.get(detector_name, 0.2)
            
            # Convertir nivel de riesgo a valor numérico
            risk_level = result.get("risk_level", "LOW")
            risk_value = self.risk_levels.get(risk_level, 1)
            
            # Obtener score y confidence
            score = result.get("score", 0.5)
            confidence = result.get("confidence", 0.5)
            
            # Aplicar pesos
            scores.append(score * weight)
            confidences.append(confidence * weight)
            risk_values.append(risk_value * weight)
            total_weight += weight
        
        # Normalizar por peso total
        final_score = sum(scores) / total_weight if total_weight > 0 else 0
        final_confidence = sum(confidences) / total_weight if total_weight > 0 else 0
        final_risk_value = sum(risk_values) / total_weight if total_weight > 0 else 1
        
        # Determinar nivel de riesgo final
        final_risk_level = self.level_names[round(final_risk_value)]
        
        return {
            "final_risk_level": final_risk_level,
            "consensus_score": final_score,
            "confidence": final_confidence,
            "detectors_count": len(detector_results),
            "method": "weighted_consensus"
        }
    
    def weighted_consensus(self, detector_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Consenso ponderado explícito usando pesos específicos
        
        Args:
            detector_results: Resultados con pesos específicos
            
        Returns:
            Resultado del consenso ponderado
        """
        weighted_scores = []
        total_weight = 0
        
        for detector_name, result in detector_results.items():
            weight = result.get("weight", 0.25)
            score = result.get("score", 0.5)
            risk_level = result.get("risk_level", "LOW")
            risk_value = self.risk_levels.get(risk_level, 1)
            
            weighted_scores.append(risk_value * weight)
            total_weight += weight
        
        # Calcular promedio ponderado
        weighted_avg = sum(weighted_scores) / total_weight if total_weight > 0 else 1
        
        # Ajustar la lógica de redondeo para favorecer niveles más altos cuando hay empate  
        if weighted_avg >= 2.2:  # Umbral más bajo para HIGH cuando hay peso significativo
            final_risk_level = "HIGH"
        elif weighted_avg >= 1.5:
            final_risk_level = "MEDIUM" 
        else:
            final_risk_level = "LOW"
        
        return {
            "final_risk_level": final_risk_level,
            "weighted_score": weighted_avg,
            "total_weight": total_weight
        }
    
    def resolve_conflicts(self, detector_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Resuelve conflictos entre detectores usando múltiples estrategias
        
        Args:
            detector_results: Resultados conflictivos de detectores
            
        Returns:
            Resultado con resolución de conflictos
        """
        risk_levels = [result.get("risk_level", "LOW") for result in detector_results.values()]
        risk_counts = Counter(risk_levels)
        
        # Estrategia 1: Mayoría simple
        most_common_risk = risk_counts.most_common(1)[0][0]
        
        # Estrategia 2: Promedio de scores
        scores = [result.get("score", 0.5) for result in detector_results.values()]
        avg_score = mean(scores)
        
        # Estrategia 3: Detector más confiable
        most_reliable = max(detector_results.items(), 
                          key=lambda x: x[1].get("confidence", 0))
        
        # Determinar método de resolución
        conflict_resolution_method = "majority_vote"
        if len(set(risk_levels)) == len(risk_levels):  # Todos diferentes
            conflict_resolution_method = "highest_confidence"
            final_risk_level = most_reliable[1].get("risk_level", "MEDIUM")
        else:
            final_risk_level = most_common_risk
        
        return {
            "final_risk_level": final_risk_level,
            "conflict_resolution_method": conflict_resolution_method,
            "consensus_score": avg_score,
            "conflicts_detected": len(set(risk_levels)) > 1,
            "most_reliable_detector": most_reliable[0]
        }
    
    def ensemble_consensus(self, ml_predictions: List[Dict[str, Any]], 
                          method: str = "voting") -> Dict[str, Any]:
        """
        Consenso usando técnicas de ensemble ML
        
        Args:
            ml_predictions: Lista de predicciones de diferentes modelos ML
            method: Método de ensemble ("voting", "averaging", "stacking")
            
        Returns:
            Resultado del consenso ensemble
        """
        if method == "voting":
            return self._voting_ensemble(ml_predictions)
        elif method == "averaging":
            return self._averaging_ensemble(ml_predictions)
        else:
            # Por defecto usar voting
            return self._voting_ensemble(ml_predictions)
    
    def _voting_ensemble(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ensemble por votación mayoritaria"""
        # Extraer predicciones (formato [LOW_prob, MEDIUM_prob, HIGH_prob])
        all_predictions = []
        for pred in predictions:
            prediction_array = pred.get("prediction", [0.33, 0.33, 0.34])
            all_predictions.append(prediction_array)
        
        # Promediar predicciones
        avg_predictions = np.mean(all_predictions, axis=0)
        
        # Determinar clase con mayor probabilidad
        predicted_class_idx = np.argmax(avg_predictions)
        predicted_class = self.level_names[predicted_class_idx + 1]  # +1 porque empezamos en 1
        
        # Calcular confianza como la probabilidad máxima
        ensemble_confidence = float(avg_predictions[predicted_class_idx])
        
        return {
            "predicted_class": predicted_class,
            "ensemble_confidence": ensemble_confidence,
            "prediction_probabilities": avg_predictions.tolist(),
            "method": "voting_ensemble"
        }
    
    def _averaging_ensemble(self, predictions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Ensemble por promediado de probabilidades"""
        # Similar al voting pero con diferentes pesos por modelo
        return self._voting_ensemble(predictions)  # Simplificado por ahora