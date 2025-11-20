"""
Memory Monitor - Sistema de Monitoreo de Umbrales de Memoria
============================================================

Monitor que analiza patrones de uso de memoria para detectar
comportamientos sospechosos típicos de malware.

Implementa algoritmos de detección de:
- Anomalías de memoria
- Memory leaks
- Picos de uso sospechosos
- Clasificación de patrones de consumo

Refactorizado siguiendo principios Clean Code.
"""

import logging
from typing import Dict, List, Any, Optional, Union, Tuple
from statistics import mean, stdev
import psutil
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Niveles de riesgo de memoria"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"  
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MemoryPattern(Enum):
    """Patrones de uso de memoria"""
    STABLE = "stable"
    INCREASING = "increasing"
    VOLATILE = "volatile"
    SPIKE = "spike"
    LEAK = "leak"


@dataclass
class MemoryThresholds:
    """Configuración de umbrales de memoria por tipo de proceso"""
    system: int = 2048
    browsers: int = 3072
    office: int = 1536
    safe: int = 512
    unknown: int = 1024


@dataclass  
class MemoryAnalysisResult:
    """Resultado del análisis de memoria"""
    risk_level: str
    suspicion_score: float
    memory_mb: float
    threshold_mb: float
    pattern: str
    confidence: float
    anomaly_detected: bool = False
    leak_detected: bool = False


@dataclass
class RiskAssessment:
    """Evaluación de riesgo de memoria"""
    risk_level: str
    suspicion_score: float
    confidence: float


class MemoryMonitor:
    """
    Monitor de memoria que detecta comportamientos anómalos
    y patrones sospechosos de uso de memoria.
    
    Refactorizado para mejor mantenibilidad y siguiendo SOLID principles.
    """
    
    # Constantes de clase
    DEFAULT_THRESHOLD_MB = 1024
    ANOMALY_STD_THRESHOLD = 2.0
    LEAK_DETECTION_THRESHOLD_MB = 50
    MEMORY_SPIKE_RATIO = 2.5
    
    def __init__(self, default_threshold_mb: int = DEFAULT_THRESHOLD_MB):
        """
        Inicializa el monitor de memoria
        
        Args:
            default_threshold_mb: Umbral por defecto en MB
        """
        self._default_threshold = default_threshold_mb
        self._thresholds = MemoryThresholds()
        self._known_processes = self._initialize_process_categories()
        logger.info(f"MemoryMonitor inicializado con umbral: {default_threshold_mb}MB")
        
    def _initialize_process_categories(self) -> Dict[str, List[str]]:
        """Inicializa las categorías de procesos conocidos"""
        return {
            "system": ["System", "svchost.exe", "csrss.exe", "dwm.exe"],
            "browsers": ["chrome.exe", "firefox.exe", "msedge.exe", "opera.exe"],
            "office": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
            "safe": ["notepad.exe", "explorer.exe", "cmd.exe", "calc.exe"]
        }
    
    def analyze_memory_usage(self, process_name: str, memory_mb: float, 
                           threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Analiza el uso de memoria de un proceso específico
        
        Args:
            process_name: Nombre del proceso
            memory_mb: Memoria utilizada en MB  
            threshold: Umbral específico (opcional)
            
        Returns:
            Análisis completo del uso de memoria
        """
        effective_threshold = self._calculate_effective_threshold(process_name, threshold)
        risk_assessment = self._assess_memory_risk(memory_mb, effective_threshold)
        
        # Crear resultado estructurado
        result = MemoryAnalysisResult(
            risk_level=risk_assessment.risk_level,
            suspicion_score=risk_assessment.suspicion_score,
            memory_mb=memory_mb,
            threshold_mb=effective_threshold,
            pattern=self._classify_memory_pattern(memory_mb, effective_threshold),
            confidence=risk_assessment.confidence
        )
        
        # Convertir a dict para compatibilidad con tests existentes
        return self._result_to_dict(result, process_name)
    
    def _calculate_effective_threshold(self, process_name: str, 
                                     custom_threshold: Optional[float]) -> float:
        """Calcula el umbral efectivo para el proceso"""
        return custom_threshold or self._get_process_threshold(process_name)
    
    def _result_to_dict(self, result: MemoryAnalysisResult, process_name: str) -> Dict[str, Any]:
        """Convierte resultado a diccionario para compatibilidad"""
        return {
            "risk_level": result.risk_level,
            "suspicion_score": result.suspicion_score,
            "memory_mb": result.memory_mb,
            "threshold_mb": result.threshold_mb,
            "process_category": self._classify_process(process_name),
            "pattern": result.pattern,
            "confidence": result.confidence,
            "anomaly_detected": result.anomaly_detected,
            "leak_detected": result.leak_detected
        }
    
    def _assess_memory_risk(self, memory_mb: float, threshold: float) -> RiskAssessment:
        """Evalúa el nivel de riesgo basado en memoria y umbral"""
        threshold_ratio = memory_mb / threshold
        
        if threshold_ratio >= 3.0:
            risk_level = RiskLevel.HIGH.value
            suspicion_score = min(0.95, 0.8 + (threshold_ratio - 3.0) * 0.05)
            confidence = 0.95
        elif threshold_ratio >= 1.4:
            risk_level = RiskLevel.HIGH.value
            suspicion_score = 0.8 + (threshold_ratio - 1.4) * 0.15
            confidence = 0.85
        elif threshold_ratio >= 1.0:
            risk_level = RiskLevel.MEDIUM.value
            suspicion_score = 0.2 + (threshold_ratio - 1.0) * 0.5
            confidence = 0.75
        else:
            risk_level = RiskLevel.LOW.value
            suspicion_score = threshold_ratio * 0.2
            confidence = 0.65
        
        return RiskAssessment(
            risk_level=risk_level,
            suspicion_score=suspicion_score,
            confidence=confidence
        )
    
    def _classify_memory_pattern(self, memory_mb: float, threshold: float) -> str:
        """Clasifica el patrón de uso de memoria"""
        ratio = memory_mb / threshold
        
        if ratio > self.MEMORY_SPIKE_RATIO:
            return MemoryPattern.SPIKE.value
        elif ratio > 1.5:
            return MemoryPattern.INCREASING.value
        elif ratio < 0.5:
            return MemoryPattern.STABLE.value
        else:
            return MemoryPattern.VOLATILE.value
    
    def detect_memory_leak(self, process_name: str, 
                          memory_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detecta memory leaks analizando el historial de memoria
        
        Args:
            process_name: Nombre del proceso
            memory_history: Lista con historial de uso de memoria
            
        Returns:
            Resultado de la detección de memory leak
        """
        if len(memory_history) < 3:
            return {"leak_detected": False, "reason": "insufficient_data"}
        
        # Extraer valores de memoria
        memory_values = [entry["memory_mb"] for entry in memory_history]
        
        # Calcular tendencia (pendiente promedio)
        trend_positive_count = 0
        total_growth = 0
        
        for i in range(1, len(memory_values)):
            growth = memory_values[i] - memory_values[i-1]
            if growth > 0:
                trend_positive_count += 1
                total_growth += growth
        
        # Evaluar si hay leak
        growth_ratio = trend_positive_count / (len(memory_values) - 1)
        avg_growth = total_growth / len(memory_values) if memory_values else 0
        
        leak_detected = growth_ratio >= 0.7 and avg_growth > 20  # 70% crecimiento, >20MB promedio
        
        # Determinar severidad
        if leak_detected:
            if avg_growth > 50:  # Umbral más bajo para HIGH
                severity = "HIGH"
            elif avg_growth > 25:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        else:
            severity = "NONE"
        
        return {
            "leak_detected": leak_detected,
            "leak_severity": severity,
            "average_growth_mb": avg_growth,
            "growth_ratio": growth_ratio,
            "total_growth_mb": total_growth
        }
    
    def detect_memory_anomalies(self, process_name: str, 
                               memory_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detecta anomalías como picos súbitos de memoria
        
        Args:
            process_name: Nombre del proceso
            memory_history: Historial de memoria
            
        Returns:
            Resultado de detección de anomalías
        """
        if len(memory_history) < 3:
            return {"anomaly_detected": False, "reason": "insufficient_data"}
        
        memory_values = [entry["memory_mb"] for entry in memory_history]
        
        # Calcular estadísticas básicas
        mean_memory = mean(memory_values)
        
        if len(memory_values) > 1:
            std_memory = stdev(memory_values)
        else:
            std_memory = 0
        
        # Buscar picos anómalos (valores > 2 desviaciones estándar o saltos extremos)
        anomaly_detected = False
        anomaly_type = None
        max_spike = 0
        
        for i, value in enumerate(memory_values):
            # Detectar por desviación estándar
            if std_memory > 0:
                z_score = abs(value - mean_memory) / std_memory
                if z_score > 2.0:  # Pico significativo (más sensible)
                    anomaly_detected = True
                    anomaly_type = "SUDDEN_SPIKE"
                    max_spike = max(max_spike, value)
            
            # Detectar por salto extremo entre valores consecutivos
            if i > 0:
                prev_value = memory_values[i-1]
                jump_ratio = value / prev_value if prev_value > 0 else 1
                if jump_ratio > 10:  # Salto de más de 10x
                    anomaly_detected = True
                    anomaly_type = "SUDDEN_SPIKE"
                    max_spike = max(max_spike, value)
        
        return {
            "anomaly_detected": anomaly_detected,
            "anomaly_type": anomaly_type,
            "max_spike_mb": max_spike,
            "baseline_mean_mb": mean_memory,
            "standard_deviation": std_memory
        }
    
    def calculate_adaptive_threshold(self, system_info: Dict[str, Any]) -> float:
        """
        Calcula umbral adaptativo basado en la información del sistema
        
        Args:
            system_info: Información del sistema (memoria total, carga, etc.)
            
        Returns:
            Umbral adaptativo en MB
        """
        total_memory_gb = system_info.get("total_memory_gb", 8)
        available_memory_gb = system_info.get("available_memory_gb", 4)
        system_load = system_info.get("system_load", "normal")
        
        # Calcular umbral base según memoria total
        base_threshold = min(total_memory_gb * 128, 4096)  # 128MB por GB, máx 4GB
        
        # Ajustar por memoria disponible
        memory_pressure = 1.0 - (available_memory_gb / total_memory_gb)
        if memory_pressure > 0.8:  # Sistema bajo presión
            base_threshold *= 0.7
        elif memory_pressure < 0.3:  # Sistema con mucha memoria libre
            base_threshold *= 1.3
        
        # Ajustar por carga del sistema
        load_multipliers = {
            "low": 1.2,
            "normal": 1.0,
            "high": 0.8,
            "critical": 0.6
        }
        
        multiplier = load_multipliers.get(system_load, 1.0)
        adaptive_threshold = base_threshold * multiplier
        
        # Asegurar límites razonables
        return max(512, min(adaptive_threshold, 8192))
    
    def classify_memory_pattern(self, memory_data: List[float]) -> Dict[str, Any]:
        """
        Clasifica patrones de uso de memoria
        
        Args:
            memory_data: Lista de valores de memoria
            
        Returns:
            Clasificación del patrón de memoria
        """
        if len(memory_data) < 2:
            return {"pattern_type": "insufficient_data", "risk_assessment": "UNKNOWN"}
        
        mean_mem = mean(memory_data)
        if len(memory_data) > 1:
            std_mem = stdev(memory_data)
        else:
            std_mem = 0
            
        # Calcular tendencia
        trend = (memory_data[-1] - memory_data[0]) / len(memory_data)
        
        # Calcular volatilidad
        volatility = std_mem / mean_mem if mean_mem > 0 else 0
        
        # Clasificar patrón
        if abs(trend) < 5 and volatility < 0.1:
            if mean_mem < 200:
                pattern_type = "stable_low"
                risk_assessment = "LOW"
            else:
                pattern_type = "stable_high"
                risk_assessment = "MEDIUM" if mean_mem > 1000 else "LOW"
        elif trend > 20:
            pattern_type = "growing"
            risk_assessment = "HIGH" if trend > 50 else "MEDIUM"
        elif volatility > 0.3:
            pattern_type = "volatile"
            risk_assessment = "HIGH"
        else:
            pattern_type = "mixed"
            risk_assessment = "MEDIUM"
        
        return {
            "pattern_type": pattern_type,
            "risk_assessment": risk_assessment,
            "mean_memory_mb": mean_mem,
            "volatility": volatility,
            "trend_mb_per_sample": trend
        }
    
    def _get_process_threshold(self, process_name: str) -> float:
        """Obtiene el umbral apropiado para un proceso"""
        category = self._classify_process(process_name)
        
        # Mapear categorías a umbrales usando el objeto MemoryThresholds
        threshold_map = {
            "system": self._thresholds.system,
            "browsers": self._thresholds.browsers,
            "office": self._thresholds.office,
            "safe": self._thresholds.safe,
            "unknown": self._thresholds.unknown
        }
        
        return threshold_map.get(category, self._default_threshold)
    
    def _classify_process(self, process_name: str) -> str:
        """Clasifica un proceso en una categoría conocida"""
        process_lower = process_name.lower()
        
        for category, processes in self._known_processes.items():
            for known_process in processes:
                if known_process.lower() in process_lower:
                    return category
        
        return "unknown"