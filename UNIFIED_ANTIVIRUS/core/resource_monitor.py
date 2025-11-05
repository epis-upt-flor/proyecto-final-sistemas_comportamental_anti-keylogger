"""
Resource Monitor - Monitoreo de recursos del sistema
Implementación para TDD #4: CPU Monitoring

Esta clase implementa el monitoreo de CPU para detectar procesos sospechosos
que consumen recursos de manera anómala, típico de keyloggers y malware.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from functools import wraps


class RiskLevel(Enum):
    """Niveles de riesgo estándar"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AnomalyType(Enum):
    """Tipos de anomalías detectables"""

    SUDDEN_SPIKE = "SUDDEN_SPIKE"
    SUSTAINED_HIGH = "SUSTAINED_HIGH"
    MEMORY_LEAK = "MEMORY_LEAK"
    VOLATILE_PATTERN = "VOLATILE_PATTERN"


class PatternType(Enum):
    """Tipos de patrones de comportamiento"""

    STABLE_LOW = "stable_low"
    STABLE_HIGH = "stable_high"
    GROWING = "growing"
    VOLATILE = "volatile"
    NORMAL = "normal"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class CPUReading:
    """Lectura de CPU para análisis temporal"""

    timestamp: str
    cpu_usage: float
    process_name: str


def performance_monitor(func):
    """Decorator para monitorear performance de funciones"""

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        start_time = time.time()
        try:
            result = func(self, *args, **kwargs)
            execution_time = time.time() - start_time
            self.logger.debug(f"{func.__name__} ejecutado en {execution_time:.4f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(
                f"{func.__name__} falló después de {execution_time:.4f}s: {e}"
            )
            raise

    return wrapper


class ResourceMonitor:
    """Monitor de recursos del sistema para detección de anomalías"""

    def __init__(self, config: Optional[Dict] = None):
        """
        Inicializa el monitor de recursos

        Args:
            config: Configuración del monitor
        """
        self.config = config or self._get_default_config()
        self.cpu_history: List[CPUReading] = []
        self.thresholds = {
            "suspicious": self.config.get("cpu_threshold_suspicious", 80.0),
            "high_risk": self.config.get("cpu_threshold_high_risk", 90.0),
        }

        # Configurar logger
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        # Métricas de performance
        self.metrics = {
            "analyses_performed": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "total_execution_time": 0.0,
        }

    def _get_default_config(self) -> Dict:
        """Configuración por defecto"""
        return {
            "cpu_threshold_suspicious": 80.0,
            "cpu_threshold_high_risk": 90.0,
            "min_duration_seconds": 60,
            "spike_threshold_multiplier": 3.0,
        }

    @performance_monitor
    def analyze_cpu_usage(
        self, process_name: str, cpu_usage: float, duration: int = 0
    ) -> Dict[str, Any]:
        """
        Analiza el uso de CPU de un proceso

        Args:
            process_name: Nombre del proceso
            cpu_usage: Porcentaje de CPU (0-100)
            duration: Duración en segundos

        Returns:
            Dict con análisis del riesgo
        """
        risk_assessment = self._calculate_cpu_risk(cpu_usage, duration)

        return {
            "process_name": process_name,
            "cpu_usage": cpu_usage,
            "duration": duration,
            "risk_level": risk_assessment["level"].value,
            "suspicion_score": risk_assessment["score"],
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threshold_exceeded": cpu_usage >= self.thresholds["suspicious"],
            "risk_factors": risk_assessment["factors"],
        }

    def _calculate_cpu_risk(self, cpu_usage: float, duration: int) -> Dict[str, Any]:
        """
        Calcula el riesgo basado en CPU y duración

        Args:
            cpu_usage: Porcentaje de CPU
            duration: Duración en segundos

        Returns:
            Dict con nivel de riesgo, score y factores
        """
        factors = []

        if cpu_usage >= self.thresholds["high_risk"]:
            level = RiskLevel.HIGH
            score = 0.95
            factors.append(f"CPU crítico: {cpu_usage}%")
        elif cpu_usage >= self.thresholds["suspicious"]:
            level = RiskLevel.HIGH  # Cualquier CPU > 80% es HIGH risk
            score = 0.85
            factors.append(f"CPU sospechoso: {cpu_usage}%")
            if duration > 300:
                factors.append(f"Duración sostenida: {duration}s")
                score = min(score + 0.05, 0.95)
        else:
            level = RiskLevel.LOW
            score = cpu_usage / 100.0 * 0.5  # Máximo 0.5 para uso normal
            factors.append(f"CPU normal: {cpu_usage}%")

        return {"level": level, "score": score, "factors": factors}

    @performance_monitor
    def detect_cpu_anomalies(
        self, process_name: str, cpu_history: List[Dict]
    ) -> Dict[str, Any]:
        """
        Detecta anomalías en el historial de CPU

        Args:
            process_name: Nombre del proceso
            cpu_history: Lista de lecturas históricas

        Returns:
            Dict con análisis de anomalías
        """
        if len(cpu_history) < 2:
            return self._create_no_anomaly_result(process_name)

        stats = self._calculate_cpu_statistics(cpu_history)
        anomaly_result = self._detect_spike_anomaly(stats)

        return {
            "anomaly_detected": anomaly_result["detected"],
            "anomaly_type": (
                anomaly_result["type"].value if anomaly_result["type"] else None
            ),
            "process_name": process_name,
            "avg_cpu": stats["avg"],
            "max_cpu": stats["max"],
            "spike_threshold": anomaly_result["threshold"],
            "analysis_details": {
                "readings_count": len(cpu_history),
                "cpu_variance": stats["variance"],
                "confidence": anomaly_result["confidence"],
            },
        }

    def _create_no_anomaly_result(self, process_name: str) -> Dict[str, Any]:
        """Crea resultado cuando no hay datos suficientes"""
        return {
            "anomaly_detected": False,
            "anomaly_type": None,
            "process_name": process_name,
            "reason": "insufficient_data",
        }

    def _calculate_cpu_statistics(self, cpu_history: List[Dict]) -> Dict[str, float]:
        """Calcula estadísticas de CPU"""
        cpu_values = [reading["cpu"] for reading in cpu_history]
        return {
            "avg": sum(cpu_values) / len(cpu_values),
            "max": max(cpu_values),
            "min": min(cpu_values),
            "variance": max(cpu_values) - min(cpu_values),
        }

    def _detect_spike_anomaly(self, stats: Dict[str, float]) -> Dict[str, Any]:
        """Detecta anomalías de tipo pico"""
        spike_threshold = stats["avg"] * self.config["spike_threshold_multiplier"]

        detected = stats["max"] > spike_threshold and stats["max"] > 50.0
        confidence = (
            min((stats["max"] / spike_threshold) * 0.8, 0.95) if detected else 0.0
        )

        return {
            "detected": detected,
            "type": AnomalyType.SUDDEN_SPIKE if detected else None,
            "threshold": spike_threshold,
            "confidence": confidence,
        }

    def analyze_sustained_cpu_usage(
        self, process_name: str, cpu_history: List[Dict]
    ) -> Dict[str, Any]:
        """
        Analiza uso sostenido de CPU (típico de keyloggers)

        Args:
            process_name: Nombre del proceso
            cpu_history: Lista de lecturas históricas

        Returns:
            Dict con análisis de uso sostenido
        """
        if len(cpu_history) < 5:  # Mínimo 5 lecturas para análisis
            return self._create_insufficient_data_result(process_name)

        sustained_analysis = self._analyze_cpu_sustainability(cpu_history)
        risk_assessment = self._assess_sustained_risk(sustained_analysis)

        return {
            "risk_level": risk_assessment["level"].value,
            "sustained_anomaly": risk_assessment["anomaly"],
            "process_name": process_name,
            "high_cpu_percentage": sustained_analysis["percentage"],
            "high_cpu_readings": sustained_analysis["high_readings"],
            "total_readings": len(cpu_history),
            "analysis_period": f"{len(cpu_history)} minutes",
            "pattern_analysis": sustained_analysis["pattern"],
            "keylogger_indicators": self._check_keylogger_indicators(
                sustained_analysis
            ),
        }

    def _create_insufficient_data_result(self, process_name: str) -> Dict[str, Any]:
        """Resultado para datos insuficientes"""
        return {
            "risk_level": RiskLevel.LOW.value,
            "sustained_anomaly": False,
            "process_name": process_name,
            "reason": "insufficient_readings",
        }

    def _analyze_cpu_sustainability(self, cpu_history: List[Dict]) -> Dict[str, Any]:
        """Analiza la sostenibilidad del uso de CPU"""
        high_cpu_readings = sum(
            1
            for reading in cpu_history
            if reading["cpu"] >= self.thresholds["suspicious"]
        )

        percentage = high_cpu_readings / len(cpu_history)

        # Análisis de patrón temporal
        pattern = (
            "consistent"
            if percentage >= 0.8
            else (
                "frequent"
                if percentage >= 0.5
                else "occasional" if percentage >= 0.2 else "rare"
            )
        )

        return {
            "high_readings": high_cpu_readings,
            "percentage": percentage,
            "pattern": pattern,
            "consistency_score": percentage,
        }

    def _assess_sustained_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Evalúa el riesgo de uso sostenido"""
        percentage = analysis["percentage"]

        if percentage >= 0.7:  # 70% del tiempo con CPU alto
            level = RiskLevel.HIGH
            anomaly = True
        elif percentage >= 0.4:  # 40% del tiempo
            level = RiskLevel.MEDIUM
            anomaly = False
        else:
            level = RiskLevel.LOW
            anomaly = False

        return {
            "level": level,
            "anomaly": anomaly,
            "confidence": min(percentage * 1.2, 0.95),
        }

    def _check_keylogger_indicators(self, analysis: Dict[str, Any]) -> List[str]:
        """Verifica indicadores específicos de keyloggers"""
        indicators = []

        if analysis["pattern"] == "consistent":
            indicators.append("consistent_high_cpu")

        if analysis["percentage"] >= 0.6:
            indicators.append("sustained_resource_consumption")

        return indicators

    def set_cpu_threshold(self, threshold_type: str, value: float):
        """
        Configura umbrales de CPU

        Args:
            threshold_type: Tipo de umbral ('suspicious', 'high_risk')
            value: Valor del umbral (0-100)
        """
        if threshold_type in self.thresholds:
            self.thresholds[threshold_type] = value
        else:
            raise ValueError(f"Unknown threshold type: {threshold_type}")

    def get_cpu_thresholds(self) -> Dict[str, float]:
        """
        Obtiene los umbrales actuales de CPU

        Returns:
            Dict con umbrales configurados
        """
        return self.thresholds.copy()

    def calculate_adaptive_threshold(self, system_info: Dict) -> float:
        """
        Calcula umbral adaptativo basado en las características del sistema

        Args:
            system_info: Información del sistema

        Returns:
            Umbral adaptativo calculado
        """
        base_threshold = 1024  # MB base

        total_memory_gb = system_info.get("total_memory_gb", 8)
        system_load = system_info.get("system_load", "normal")

        # Ajustar según memoria total
        if total_memory_gb >= 16:
            adaptive_threshold = base_threshold * 2  # 2GB para sistemas con mucha RAM
        elif total_memory_gb >= 8:
            adaptive_threshold = base_threshold * 1.5  # 1.5GB para sistemas normales
        else:
            adaptive_threshold = base_threshold  # 1GB para sistemas con poca RAM

        # Ajustar según carga del sistema
        if system_load == "high":
            adaptive_threshold *= 0.8  # Más restrictivo si el sistema está cargado
        elif system_load == "low":
            adaptive_threshold *= 1.2  # Más permisivo si el sistema está libre

        return adaptive_threshold

    def classify_memory_pattern(self, memory_data: List[float]) -> Dict[str, Any]:
        """
        Clasifica patrones de uso de memoria usando análisis mejorado

        Args:
            memory_data: Lista de valores de memoria

        Returns:
            Dict con clasificación del patrón
        """
        if len(memory_data) < 3:
            return self._create_insufficient_memory_data_result()

        stats = self._calculate_memory_statistics(memory_data)
        pattern_analysis = self._analyze_memory_patterns(memory_data, stats)

        return {
            "pattern_type": pattern_analysis["type"].value,
            "risk_assessment": pattern_analysis["risk"],
            "statistics": stats,
            "malware_indicators": pattern_analysis["indicators"],
            "confidence": pattern_analysis["confidence"],
        }

    def _create_insufficient_memory_data_result(self) -> Dict[str, Any]:
        """Resultado para datos de memoria insuficientes"""
        return {
            "pattern_type": PatternType.INSUFFICIENT_DATA.value,
            "risk_assessment": "unknown",
            "reason": "need_at_least_3_readings",
        }

    def _calculate_memory_statistics(
        self, memory_data: List[float]
    ) -> Dict[str, float]:
        """Calcula estadísticas completas de memoria"""
        avg_memory = sum(memory_data) / len(memory_data)
        max_memory = max(memory_data)
        min_memory = min(memory_data)
        variance = max_memory - min_memory

        # Calcular tendencia
        growth_rate = (
            (memory_data[-1] - memory_data[0]) / memory_data[0]
            if memory_data[0] > 0
            else 0
        )

        return {
            "average": avg_memory,
            "maximum": max_memory,
            "minimum": min_memory,
            "variance": variance,
            "growth_rate": growth_rate,
            "volatility": variance / avg_memory if avg_memory > 0 else 0,
        }

    def _analyze_memory_patterns(
        self, memory_data: List[float], stats: Dict[str, float]
    ) -> Dict[str, Any]:
        """Analiza patrones de memoria y detecta indicadores maliciosos"""
        # Detectar patrones
        is_growing = stats["growth_rate"] > 0.5  # Crecimiento > 50%
        is_volatile = stats["volatility"] > 0.5  # Variabilidad > 50%
        is_stable_high = stats["average"] > 1000 and stats["volatility"] < 0.2
        is_stable_low = stats["average"] < 200 and stats["volatility"] < 0.3

        # Clasificar
        if is_growing:
            pattern_type = PatternType.GROWING
            risk = "high" if stats["average"] > 500 else "medium"
            confidence = 0.8
            indicators = ["memory_growth", "potential_leak"]
        elif is_volatile:
            pattern_type = PatternType.VOLATILE
            risk = "medium"
            confidence = 0.7
            indicators = ["unstable_behavior", "resource_thrashing"]
        elif is_stable_high:
            pattern_type = PatternType.STABLE_HIGH
            risk = "medium"
            confidence = 0.9
            indicators = ["high_resource_consumption"]
        elif is_stable_low:
            pattern_type = PatternType.STABLE_LOW
            risk = "low"
            confidence = 0.9
            indicators = ["normal_behavior"]
        else:
            pattern_type = PatternType.NORMAL
            risk = "low"
            confidence = 0.8
            indicators = ["standard_usage"]

        return {
            "type": pattern_type,
            "risk": risk,
            "confidence": confidence,
            "indicators": indicators,
        }

    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Obtiene métricas de performance del monitor

        Returns:
            Dict con métricas de rendimiento
        """
        return {
            "analyses_performed": self.metrics["analyses_performed"],
            "anomalies_detected": self.metrics["anomalies_detected"],
            "detection_rate": (
                self.metrics["anomalies_detected"]
                / max(self.metrics["analyses_performed"], 1)
            )
            * 100,
            "avg_execution_time": self.metrics["total_execution_time"]
            / max(self.metrics["analyses_performed"], 1),
            "total_execution_time": self.metrics["total_execution_time"],
            "uptime": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def reset_metrics(self):
        """Reinicia las métricas de performance"""
        self.metrics = {
            "analyses_performed": 0,
            "anomalies_detected": 0,
            "false_positives": 0,
            "total_execution_time": 0.0,
        }
        self.logger.info("Métricas de performance reiniciadas")
