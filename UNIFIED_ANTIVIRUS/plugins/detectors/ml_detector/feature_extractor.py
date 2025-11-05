"""
Feature Extractor - Extracción de Características para ML
========================================================

Sistema de extracción y normalización de características para modelos
de Machine Learning del antivirus. Optimizado para detectar malware y keyloggers.
"""

import logging
import time
import functools
import math
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from collections import defaultdict, OrderedDict
import hashlib
import json


class LRUCache:
    """Cache LRU optimizado para features computados"""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Obtiene valor del cache"""
        if key in self.cache:
            self.hits += 1
            # Mover al final (más reciente)
            value = self.cache.pop(key)
            self.cache[key] = value
            return value
        self.misses += 1
        return None

    def put(self, key: str, value: Any):
        """Almacena valor en el cache"""
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.max_size:
            # Remover el más antiguo
            self.cache.popitem(last=False)

        self.cache[key] = value

    def get_stats(self) -> Dict[str, Any]:
        """Estadísticas del cache"""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0.0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "size": len(self.cache),
            "max_size": self.max_size,
        }


def performance_monitor(func):
    """Decorador mejorado para monitoreo de performance con métricas"""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        start_time = time.time()
        method_name = func.__name__

        try:
            result = func(self, *args, **kwargs)
            execution_time = time.time() - start_time

            # Actualizar métricas de performance
            if hasattr(self, "performance_metrics"):
                if method_name not in self.performance_metrics:
                    self.performance_metrics[method_name] = {
                        "total_calls": 0,
                        "total_time": 0.0,
                        "avg_time": 0.0,
                        "max_time": 0.0,
                        "min_time": float("inf"),
                    }

                metrics = self.performance_metrics[method_name]
                metrics["total_calls"] += 1
                metrics["total_time"] += execution_time
                metrics["avg_time"] = metrics["total_time"] / metrics["total_calls"]
                metrics["max_time"] = max(metrics["max_time"], execution_time)
                metrics["min_time"] = min(metrics["min_time"], execution_time)

            # Logging inteligente
            if execution_time > 0.1:
                self.logger.warning(
                    f"⚠️ Extracción lenta: {method_name} tomó {execution_time:.3f}s"
                )
            elif execution_time > 0.05:
                self.logger.info(f"🐌 {method_name} moderado en {execution_time:.3f}s")
            else:
                self.logger.debug(f"⚡ {method_name} rápido en {execution_time:.3f}s")

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(
                f"❌ Error en {method_name} después de {execution_time:.3f}s: {e}"
            )
            raise

    return wrapper


class FeatureExtractor:
    """
    Extractor de características para ML del sistema antivirus.

    Responsabilidades:
    - Extraer features de procesos sospechosos
    - Normalizar características para ML
    - Clasificar APIs por nivel de riesgo
    - Analizar patrones de comportamiento
    - Seleccionar features más relevantes
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Inicializa el extractor de características refactorizado

        Args:
            config: Configuración del extractor
        """
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._setup_logging()

        # Bases de conocimiento para features
        self.api_risk_db = self._initialize_api_risk_database()
        self.behavioral_patterns = self._initialize_behavioral_patterns()
        self.feature_weights = self._initialize_feature_weights()

        # Sistemas de optimización
        self.cache = (
            LRUCache(max_size=self.config.get("cache_size", 1000))
            if self.config.get("enable_cache")
            else None
        )
        self.performance_metrics = {}
        self.extraction_stats = defaultdict(int)

        # Pre-compilar patrones frecuentes
        self._precompute_optimization_data()

        self.logger.info("🚀 FeatureExtractor refactorizado inicializado correctamente")

    def _setup_logging(self):
        """Configura logging optimizado para extractor"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto del extractor refactorizado"""
        return {
            "normalization_method": "min_max",
            "feature_selection_method": "importance",
            "api_risk_threshold": 0.7,
            "behavioral_window_size": 100,
            "max_features": 50,
            "enable_cache": True,
            "cache_size": 1000,
            "batch_processing": True,
            "parallel_processing": False,
            "feature_quality_threshold": 0.1,
            "enable_feature_validation": True,
        }

    def _precompute_optimization_data(self):
        """Pre-computa datos para optimización"""
        # Pre-calcular sets de APIs por categoría para búsqueda rápida
        self.high_risk_apis = {
            api for api, risk in self.api_risk_db.items() if risk > 0.8
        }
        self.medium_risk_apis = {
            api for api, risk in self.api_risk_db.items() if 0.5 < risk <= 0.8
        }
        self.low_risk_apis = {
            api for api, risk in self.api_risk_db.items() if risk <= 0.5
        }

        # Pre-calcular estadísticas para normalización
        risk_values = list(self.api_risk_db.values())
        self.api_risk_stats = {
            "mean": sum(risk_values) / len(risk_values),
            "min": min(risk_values),
            "max": max(risk_values),
            "std": math.sqrt(
                sum((x - sum(risk_values) / len(risk_values)) ** 2 for x in risk_values)
                / len(risk_values)
            ),
        }

    def _initialize_api_risk_database(self) -> Dict[str, float]:
        """Base de datos de APIs y su nivel de riesgo (0.0-1.0)"""
        return {
            # APIs críticas de keylogging
            "SetWindowsHookExW": 0.95,
            "SetWindowsHookExA": 0.95,
            "GetAsyncKeyState": 0.90,
            "GetKeyState": 0.85,
            "RegisterHotKey": 0.80,
            # APIs de inyección de código
            "CreateRemoteThread": 0.92,
            "WriteProcessMemory": 0.88,
            "VirtualAllocEx": 0.85,
            "OpenProcess": 0.75,
            # APIs de red sospechosas
            "WSASocket": 0.60,
            "connect": 0.55,
            "send": 0.50,
            "recv": 0.50,
            # APIs de archivos normales
            "CreateFileW": 0.30,
            "WriteFile": 0.25,
            "ReadFile": 0.20,
            "CloseHandle": 0.10,
        }

    def _initialize_behavioral_patterns(self) -> Dict[str, Dict]:
        """Patrones de comportamiento conocidos"""
        return {
            "keylogger_pattern": {
                "high_cpu_spikes": True,
                "frequent_api_calls": True,
                "hidden_execution": True,
                "network_activity": True,
                "weight": 0.9,
            },
            "normal_pattern": {
                "stable_cpu": True,
                "predictable_memory": True,
                "legitimate_apis": True,
                "weight": 0.1,
            },
        }

    def _initialize_feature_weights(self) -> Dict[str, float]:
        """Pesos de importancia de cada tipo de feature"""
        return {
            "api_hooking_score": 0.25,
            "resource_anomaly_score": 0.20,
            "network_risk_score": 0.18,
            "behavioral_score": 0.15,
            "cpu_usage_normalized": 0.12,
            "memory_usage_normalized": 0.10,
        }

    @performance_monitor
    def extract_features(self, process_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extracción principal de características optimizada con cache

        Args:
            process_data: Datos del proceso a analizar

        Returns:
            Diccionario con features extraídas y normalizadas
        """
        # Generar cache key basado en el contenido
        cache_key = self._generate_cache_key(process_data) if self.cache else None

        if cache_key and self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                self.extraction_stats["cache_hits"] += 1
                self.logger.debug(
                    f"💰 Cache HIT para proceso {process_data.get('name', 'unknown')}"
                )
                return cached_result
            self.extraction_stats["cache_misses"] += 1

        features = {}

        try:
            # Extraer features por categoría con optimización
            extraction_tasks = [
                (
                    "api",
                    lambda: self.extract_api_features(
                        process_data.get("api_calls", [])
                    ),
                ),
                ("behavioral", lambda: self.extract_behavioral_features(process_data)),
                ("resource", lambda: self._extract_resource_features(process_data)),
                ("network", lambda: self._extract_network_features(process_data)),
            ]

            for category, extractor_func in extraction_tasks:
                category_features = extractor_func()
                if category_features:
                    features.update(category_features)
                    self.extraction_stats[f"{category}_features_extracted"] += len(
                        category_features
                    )

            # Validar calidad de features si está habilitado
            if self.config.get("enable_feature_validation", True):
                features = self._validate_feature_quality(features)

            # Normalizar features con método optimizado
            normalized_features = self.normalize_features(features)

            # Cachear resultado si está habilitado
            if cache_key and self.cache and normalized_features:
                self.cache.put(cache_key, normalized_features)

            self.extraction_stats["total_extractions"] += 1
            self.logger.info(
                f"✅ Extraídas {len(normalized_features)} características del proceso {process_data.get('name', 'unknown')}"
            )
            return normalized_features

        except Exception as e:
            self.extraction_stats["extraction_errors"] += 1
            self.logger.error(f"❌ Error extrayendo features: {e}")
            return {}

    def _generate_cache_key(self, process_data: Dict[str, Any]) -> str:
        """Genera una clave única para el cache basada en los datos del proceso"""
        # Crear un hash de los datos relevantes para cache
        relevant_data = {
            "name": process_data.get("name", ""),
            "cpu_usage": process_data.get("cpu_usage", 0),
            "memory_usage": process_data.get("memory_usage", 0),
            "api_calls": sorted(
                process_data.get("api_calls", [])
            ),  # Ordenar para consistencia
            "file_operations": process_data.get("file_operations", []),
            "network_connections": process_data.get("network_connections", []),
        }

        # Generar hash MD5 de los datos serializados
        data_str = json.dumps(relevant_data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()

    def _validate_feature_quality(self, features: Dict[str, float]) -> Dict[str, float]:
        """Valida la calidad de las features extraídas"""
        quality_threshold = self.config.get("feature_quality_threshold", 0.1)
        validated_features = {}

        for name, value in features.items():
            # Validaciones básicas
            if not isinstance(value, (int, float)):
                self.logger.warning(f"⚠️ Feature '{name}' no es numérico: {type(value)}")
                continue

            if math.isnan(value) or math.isinf(value):
                self.logger.warning(f"⚠️ Feature '{name}' tiene valor inválido: {value}")
                continue

            # Validar rango razonable
            if abs(value) < quality_threshold and name not in [
                "hooking_apis_count",
                "keylogging_apis_ratio",
            ]:
                self.logger.debug(f"🔍 Feature '{name}' muy pequeño: {value}")

            validated_features[name] = float(value)

        removed_count = len(features) - len(validated_features)
        if removed_count > 0:
            self.logger.info(f"🧹 Eliminadas {removed_count} features de baja calidad")

        return validated_features

    @performance_monitor
    def extract_api_features(self, api_calls: List[str]) -> Dict[str, float]:
        """
        Extracción optimizada de características de APIs con sets pre-computados

        Args:
            api_calls: Lista de nombres de APIs llamadas

        Returns:
            Features relacionadas con APIs
        """
        if not api_calls:
            return {"hooking_apis_count": 0.0, "keylogging_apis_ratio": 0.0}

        # Usar sets pre-computados para búsqueda O(1)
        api_set = set(api_calls)
        high_risk_count = len(api_set & self.high_risk_apis)
        medium_risk_count = len(api_set & self.medium_risk_apis)
        low_risk_count = len(api_set & self.low_risk_apis)

        # Calcular métricas optimizadas
        total_apis = len(api_calls)
        unique_apis = len(api_set)

        # Ratios de riesgo
        keylogging_ratio = high_risk_count / total_apis if total_apis > 0 else 0.0
        medium_risk_ratio = medium_risk_count / total_apis if total_apis > 0 else 0.0

        # Score de riesgo ponderado (más eficiente)
        total_risk_score = 0.0
        for api in api_set:
            risk = self.api_risk_db.get(api, 0.1)
            count = api_calls.count(api)
            total_risk_score += risk * count

        avg_risk_score = total_risk_score / total_apis if total_apis > 0 else 0.0

        # Diversidad de APIs (entropía simplificada)
        api_diversity = unique_apis / total_apis if total_apis > 0 else 0.0

        return {
            "hooking_apis_count": float(high_risk_count),
            "keylogging_apis_ratio": keylogging_ratio,
            "medium_risk_apis_ratio": medium_risk_ratio,
            "api_risk_score_avg": avg_risk_score,
            "total_apis_count": float(total_apis),
            "unique_apis_count": float(unique_apis),
            "api_diversity_score": api_diversity,
        }

    @performance_monitor
    def extract_behavioral_features(
        self, behavior_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extrae características de comportamiento del proceso

        Args:
            behavior_data: Datos de comportamiento del proceso

        Returns:
            Features de comportamiento calculadas
        """
        features = {}

        # Análisis de estabilidad del proceso
        if "process_lifetime" in behavior_data:
            lifetime = behavior_data["process_lifetime"]
            features["process_stability_score"] = min(1.0, lifetime / 3600.0)

        # Análisis de anomalías de CPU
        if "cpu_spikes" in behavior_data:
            cpu_spikes = behavior_data["cpu_spikes"]
            if cpu_spikes:
                cpu_variance = self._calculate_variance(cpu_spikes)
                features["resource_anomaly_score"] = min(1.0, cpu_variance / 100.0)

        # Análisis de actividad de red
        if "network_activity" in behavior_data:
            network = behavior_data["network_activity"]
            connections = network.get("connections", 0)
            data_sent = network.get("data_sent", 0)

            network_score = min(1.0, (connections * 0.1 + data_sent / 10000.0))
            features["network_activity_score"] = network_score

        # Análisis de crecimiento de memoria
        if "memory_growth" in behavior_data:
            memory_growth = behavior_data["memory_growth"]
            if len(memory_growth) > 1:
                growth_rate = (memory_growth[-1] - memory_growth[0]) / len(
                    memory_growth
                )
                features["memory_growth_rate"] = min(1.0, growth_rate / 100.0)

        return features

    def _extract_resource_features(
        self, process_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extrae features de uso de recursos"""
        features = {}

        if "cpu_usage" in process_data:
            features["cpu_usage_raw"] = float(process_data["cpu_usage"])

        if "memory_usage" in process_data:
            features["memory_usage_raw"] = float(process_data["memory_usage"])

        if "file_operations" in process_data:
            operations = process_data["file_operations"]
            features["file_operations_count"] = float(
                len(operations) if isinstance(operations, list) else 0
            )

        return features

    def _extract_network_features(
        self, process_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """Extrae features de actividad de red"""
        features = {}

        if "network_connections" in process_data:
            connections = process_data["network_connections"]
            if isinstance(connections, list):
                outbound_count = sum(
                    1 for conn in connections if conn.get("direction") == "outbound"
                )
                suspicious_ports = sum(
                    1 for conn in connections if conn.get("port", 0) > 1024
                )

                features["outbound_connections"] = float(outbound_count)
                features["suspicious_ports_count"] = float(suspicious_ports)
                features["network_risk_score"] = min(
                    1.0, (outbound_count * 0.2 + suspicious_ports * 0.1)
                )

        return features

    @performance_monitor
    def normalize_features(self, raw_features: Dict[str, float]) -> Dict[str, float]:
        """
        Normalización optimizada con soporte para procesamiento batch

        Args:
            raw_features: Features sin normalizar

        Returns:
            Features normalizadas [0, 1]
        """
        if not raw_features:
            return {}

        method = self.config.get("normalization_method", "min_max")

        # Usar método optimizado según configuración
        if method == "min_max":
            return self._min_max_normalize_optimized(raw_features)
        elif method == "z_score":
            return self._z_score_normalize_optimized(raw_features)
        elif method == "robust":
            return self._robust_normalize(raw_features)
        else:
            return self._min_max_normalize_optimized(raw_features)

    def _min_max_normalize_optimized(
        self, features: Dict[str, float]
    ) -> Dict[str, float]:
        """Normalización Min-Max optimizada con manejo de casos edge"""
        if not features:
            return {}

        # Separar por tipo de feature para normalización inteligente
        api_features = {k: v for k, v in features.items() if "api" in k.lower()}
        behavioral_features = {
            k: v
            for k, v in features.items()
            if any(x in k.lower() for x in ["behavioral", "stability", "anomaly"])
        }
        resource_features = {
            k: v
            for k, v in features.items()
            if any(x in k.lower() for x in ["cpu", "memory", "file"])
        }
        network_features = {k: v for k, v in features.items() if "network" in k.lower()}

        normalized = {}

        # Normalizar cada categoría con sus propios rangos
        for category_name, category_features in [
            ("api", api_features),
            ("behavioral", behavioral_features),
            ("resource", resource_features),
            ("network", network_features),
        ]:
            if not category_features:
                continue

            values = list(category_features.values())
            min_val = min(values)
            max_val = max(values)

            # Manejo de casos edge
            if max_val == min_val:
                # Si todos los valores son iguales, normalizar a 0.5
                for key in category_features:
                    normalized[f"{key}_normalized"] = 0.5
            else:
                # Normalización estándar
                for key, value in category_features.items():
                    normalized_value = (value - min_val) / (max_val - min_val)
                    # Asegurar rango [0, 1]
                    normalized_value = max(0.0, min(1.0, normalized_value))
                    normalized[f"{key}_normalized"] = normalized_value

        return normalized

    def _z_score_normalize_optimized(
        self, features: Dict[str, float]
    ) -> Dict[str, float]:
        """Normalización Z-Score optimizada con sigmoide mejorada"""
        if not features:
            return {}

        values = list(features.values())
        n = len(values)

        # Cálculo optimizado de media y desviación estándar
        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / n
        std_dev = (
            math.sqrt(variance) if variance > 1e-8 else 1.0
        )  # Evitar división por 0

        normalized = {}
        for key, value in features.items():
            z_score = (value - mean_val) / std_dev
            # Sigmoide mejorada con mejor rango
            normalized_value = 1 / (
                1 + math.exp(-z_score * 2)
            )  # Factor 2 para mejor distribución
            normalized[f"{key}_normalized"] = normalized_value

        return normalized

    def _robust_normalize(self, features: Dict[str, float]) -> Dict[str, float]:
        """Normalización robusta usando percentiles (resistente a outliers)"""
        if not features:
            return {}

        values = sorted(features.values())
        n = len(values)

        # Calcular percentiles 25 y 75
        q1_idx = max(0, n // 4)
        q3_idx = min(n - 1, (3 * n) // 4)

        q1 = values[q1_idx]
        q3 = values[q3_idx]
        iqr = q3 - q1

        if iqr < 1e-8:  # IQR muy pequeño
            return {f"{k}_normalized": 0.5 for k in features}

        normalized = {}
        for key, value in features.items():
            # Normalización robusta
            normalized_value = (value - q1) / iqr
            # Aplicar función sigmoide suave para mapear a [0, 1]
            normalized_value = 1 / (1 + math.exp(-normalized_value))
            normalized[f"{key}_normalized"] = normalized_value

        return normalized

    def _min_max_normalize(self, features: Dict[str, float]) -> Dict[str, float]:
        """Normalización Min-Max [0, 1]"""
        if not features:
            return {}

        values = list(features.values())
        min_val = min(values)
        max_val = max(values)

        if max_val == min_val:
            return {k: 0.5 for k in features}

        normalized = {}
        for key, value in features.items():
            normalized_value = (value - min_val) / (max_val - min_val)
            normalized[
                f"{key}_normalized" if not key.endswith("_normalized") else key
            ] = normalized_value

        return normalized

    def _z_score_normalize(self, features: Dict[str, float]) -> Dict[str, float]:
        """Normalización Z-Score"""
        if not features:
            return {}

        values = list(features.values())
        mean_val = sum(values) / len(values)
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance) if variance > 0 else 1.0

        normalized = {}
        for key, value in features.items():
            z_score = (value - mean_val) / std_dev
            normalized_value = 1 / (1 + math.exp(-z_score))
            normalized[
                f"{key}_normalized" if not key.endswith("_normalized") else key
            ] = normalized_value

        return normalized

    @performance_monitor
    def select_top_features(
        self, all_features: Dict[str, float], top_k: int = 10
    ) -> Dict[str, float]:
        """
        Selecciona las K características más importantes

        Args:
            all_features: Todas las features disponibles
            top_k: Número de features a seleccionar

        Returns:
            Top K features más importantes
        """
        if not all_features or top_k <= 0:
            return {}

        # Calcular importancia basada en pesos configurados y valores
        feature_importance = {}

        for feature_name, value in all_features.items():
            base_weight = self.feature_weights.get(feature_name, 0.1)
            importance = base_weight * abs(value)
            feature_importance[feature_name] = importance

        # Ordenar por importancia y seleccionar top K
        sorted_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )
        top_features = dict(sorted_features[:top_k])

        selected_features = {name: all_features[name] for name in top_features.keys()}

        self.logger.info(
            f"Seleccionadas {len(selected_features)} características principales"
        )
        return selected_features

    def _calculate_variance(self, values: List[float]) -> float:
        """Calcula la varianza de una lista de valores"""
        if not values or len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance

    def extract_features_batch(
        self, processes_data: List[Dict[str, Any]]
    ) -> List[Dict[str, float]]:
        """
        Extracción optimizada en lote para múltiples procesos

        Args:
            processes_data: Lista de datos de procesos a analizar

        Returns:
            Lista de features extraídas para cada proceso
        """
        if not processes_data:
            return []

        batch_start_time = time.time()
        results = []

        self.logger.info(
            f"🔄 Iniciando extracción batch para {len(processes_data)} procesos"
        )

        try:
            for i, process_data in enumerate(processes_data):
                features = self.extract_features(process_data)
                results.append(features)

                # Log progreso cada 100 procesos
                if (i + 1) % 100 == 0:
                    self.logger.info(
                        f"📊 Procesados {i + 1}/{len(processes_data)} procesos"
                    )

            batch_time = time.time() - batch_start_time
            avg_time_per_process = batch_time / len(processes_data)

            self.logger.info(
                f"✅ Extracción batch completada: {len(results)} procesos en {batch_time:.2f}s (avg: {avg_time_per_process:.3f}s/proceso)"
            )

        except Exception as e:
            self.logger.error(f"❌ Error en extracción batch: {e}")

        return results

    def get_feature_info(self) -> Dict[str, Any]:
        """
        Obtiene información detallada del extractor refactorizado

        Returns:
            Información completa de configuración, estadísticas y performance
        """
        info = {
            "config": self.config,
            "api_database_size": len(self.api_risk_db),
            "behavioral_patterns": len(self.behavioral_patterns),
            "feature_weights": self.feature_weights,
            "supported_methods": ["min_max", "z_score", "robust"],
            "optimization_data": {
                "high_risk_apis": len(self.high_risk_apis),
                "medium_risk_apis": len(self.medium_risk_apis),
                "low_risk_apis": len(self.low_risk_apis),
                "api_risk_stats": self.api_risk_stats,
            },
            "extraction_stats": dict(self.extraction_stats),
            "performance_metrics": self.performance_metrics,
        }

        # Agregar estadísticas del cache si está habilitado
        if self.cache:
            info["cache_stats"] = self.cache.get_stats()

        return info

    def get_performance_report(self) -> Dict[str, Any]:
        """
        Genera un reporte completo de performance del extractor

        Returns:
            Reporte detallado de métricas de performance
        """
        total_extractions = self.extraction_stats.get("total_extractions", 0)
        total_errors = self.extraction_stats.get("extraction_errors", 0)

        success_rate = (
            ((total_extractions - total_errors) / total_extractions * 100)
            if total_extractions > 0
            else 0.0
        )

        report = {
            "summary": {
                "total_extractions": total_extractions,
                "success_rate": f"{success_rate:.1f}%",
                "total_errors": total_errors,
            },
            "feature_breakdown": {
                "api_features": self.extraction_stats.get("api_features_extracted", 0),
                "behavioral_features": self.extraction_stats.get(
                    "behavioral_features_extracted", 0
                ),
                "resource_features": self.extraction_stats.get(
                    "resource_features_extracted", 0
                ),
                "network_features": self.extraction_stats.get(
                    "network_features_extracted", 0
                ),
            },
            "cache_performance": (
                self.cache.get_stats() if self.cache else "Cache disabled"
            ),
            "method_performance": {},
        }

        # Agregar métricas detalladas por método
        for method, metrics in self.performance_metrics.items():
            if metrics["total_calls"] > 0:
                report["method_performance"][method] = {
                    "calls": metrics["total_calls"],
                    "avg_time_ms": f"{metrics['avg_time'] * 1000:.2f}",
                    "max_time_ms": f"{metrics['max_time'] * 1000:.2f}",
                    "min_time_ms": f"{metrics['min_time'] * 1000:.2f}",
                    "total_time_s": f"{metrics['total_time']:.3f}",
                }

        return report

    def reset_stats(self):
        """Reinicia todas las estadísticas y métricas"""
        self.extraction_stats.clear()
        self.performance_metrics.clear()

        if self.cache:
            self.cache = LRUCache(max_size=self.config.get("cache_size", 1000))

        self.logger.info("📊 Estadísticas del extractor reiniciadas")


# Compatibilidad - Alias para uso en plugin.py
NetworkFeatureExtractor = FeatureExtractor
