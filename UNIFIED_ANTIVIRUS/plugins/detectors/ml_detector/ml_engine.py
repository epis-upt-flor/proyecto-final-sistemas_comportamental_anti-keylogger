"""
ML Engine para Detector de Keyloggers
====================================

Motor de Machine Learning que maneja modelos ONNX y sklearn
con fallback automático y optimizaciones de rendimiento.
"""

import logging
import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Resultado de una predicción ML"""
    predictions: List[str]
    probabilities: List[float]
    prediction_time: float
    model_type: str
    confidence_scores: List[float] = None
    metadata: Dict[str, Any] = None


class ModelLoadError(Exception):
    """Error al cargar modelo"""
    pass


class PredictionError(Exception):
    """Error durante predicción"""
    pass


class MLEngine:
    """
    Motor de Machine Learning con soporte para ONNX y sklearn
    
    Implementa Strategy Pattern para diferentes tipos de modelo
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del motor ML
        """
        self.config = config
        self.ml_config = config.get('ml_config', {})
        self.models_config = config.get('models', {})
        
        # Estado del motor
        self.onnx_model = None
        self.sklearn_model = None
        self.label_classes = []
        self.feature_columns = []
        self.current_model_type = None
        
        # Configuración - asegurar ruta absoluta
        model_path_config = self.ml_config.get('model_path', 'models')
        self.model_path = Path(model_path_config)
        if not self.model_path.is_absolute():
            # Si es relativa, calcular desde el plugin
            plugin_dir = Path(__file__).parent
            self.model_path = (plugin_dir / model_path_config).resolve()
        self.use_onnx = self.ml_config.get('use_onnx', True)
        self.confidence_threshold = self.ml_config.get('confidence_threshold', 0.8)
        self.prediction_timeout = self.ml_config.get('prediction_timeout_ms', 5000) / 1000.0
        self.batch_size = self.ml_config.get('batch_size', 32)
        
        # Cache de predicciones
        self.enable_caching = self.ml_config.get('enable_caching', True)
        self.prediction_cache = {} if self.enable_caching else None
        self.cache_size = self.ml_config.get('cache_size', 1000)
        
        # Estadísticas
        self.stats = {
            'predictions_made': 0,
            'threats_detected': 0,
            'avg_prediction_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0,
            'model_load_time': 0.0,
            'errors': 0,
            'timeouts': 0
        }
        
        # Thread pool para predicciones asíncronas
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.get('performance', {}).get('max_concurrent_predictions', 4)
        )
        
        self._lock = threading.Lock()
        
        # Inicializar motor
        self._initialize_engine()
        
        logger.info(f"[ML_ENGINE] Inicializado (ONNX: {self.use_onnx}, Modelo: {self.current_model_type})")
    
    def _initialize_engine(self):
        """Inicializa el motor ML cargando modelos y metadatos"""
        try:
            start_time = time.time()
            
            # Cargar metadatos primero
            self._load_label_classes()
            self._load_feature_metadata()
            
            # Cargar modelo principal
            if self.use_onnx:
                if self._load_onnx_model():
                    self.current_model_type = 'ONNX'
                else:
                    logger.warning("[ML_ENGINE] ONNX falló, usando sklearn como fallback")
                    if self._load_sklearn_model():
                        self.current_model_type = 'sklearn'
            else:
                if self._load_sklearn_model():
                    self.current_model_type = 'sklearn'
                else:
                    logger.warning("[ML_ENGINE] sklearn falló, probando ONNX")
                    if self._load_onnx_model():
                        self.current_model_type = 'ONNX'
            
            self.stats['model_load_time'] = time.time() - start_time
            
            if not self.is_ready():
                raise ModelLoadError("No se pudo cargar ningún modelo válido")
                
            logger.info(f"[ML_ENGINE] ✅ Modelo {self.current_model_type} cargado en {self.stats['model_load_time']:.2f}s")
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] ❌ Error inicializando motor: {e}")
            raise ModelLoadError(f"Error inicializando ML Engine: {e}")
    
    def _load_onnx_model(self) -> bool:
        """Carga modelo ONNX con validación"""
        try:
            import onnxruntime as ort
            
            # Buscar modelo ONNX
            onnx_files = [
                self.models_config.get('primary_onnx', ''),
                self.models_config.get('secondary_onnx', ''),
                'modelo_keylogger_from_datos.onnx',
                'keylogger_model_large_20250918_112840.onnx'
            ]
            
            onnx_path = None
            for onnx_file in onnx_files:
                if not onnx_file:
                    continue
                    
                path = self.model_path / onnx_file
                if path.exists():
                    onnx_path = path
                    break
            
            if not onnx_path:
                logger.error(f"[ML_ENGINE] No se encontró modelo ONNX en {self.model_path}")
                return False
            
            # Configurar providers ONNX
            providers = ['CPUExecutionProvider']
            
            # Intentar GPU si está disponible
            try:
                available_providers = ort.get_available_providers()
                if 'CUDAExecutionProvider' in available_providers:
                    providers.insert(0, 'CUDAExecutionProvider')
                    logger.info("[ML_ENGINE] CUDA disponible, usando GPU")
            except Exception:
                pass
            
            # Crear sesión ONNX
            self.onnx_model = ort.InferenceSession(str(onnx_path), providers=providers)
            
            # Obtener información del modelo
            self.input_name = self.onnx_model.get_inputs()[0].name
            self.input_shape = self.onnx_model.get_inputs()[0].shape
            self.output_names = [output.name for output in self.onnx_model.get_outputs()]
            
            # Validar modelo con predicción de prueba
            test_input = np.random.randn(1, len(self.feature_columns) or 81).astype(np.float32)
            try:
                _ = self.onnx_model.run(self.output_names, {self.input_name: test_input})
                logger.info(f"[ML_ENGINE] ✅ Modelo ONNX validado: {onnx_path.name}")
                return True
            except Exception as e:
                logger.error(f"[ML_ENGINE] Modelo ONNX no válido: {e}")
                self.onnx_model = None
                return False
            
        except ImportError:
            logger.error("[ML_ENGINE] onnxruntime no está instalado")
            return False
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error cargando ONNX: {e}")
            self.onnx_model = None
            return False
    
    def _load_sklearn_model(self) -> bool:
        """Carga modelo sklearn con validación"""
        try:
            import joblib
            
            # Buscar modelo sklearn
            sklearn_files = [
                self.models_config.get('fallback_sklearn', ''),
                'rf_large_model_20250918_112442.pkl',
                'modelo_keylogger_from_datos.pkl'
            ]
            
            sklearn_path = None
            for sklearn_file in sklearn_files:
                if not sklearn_file:
                    continue
                    
                path = self.model_path / sklearn_file
                if path.exists():
                    sklearn_path = path
                    break
            
            if not sklearn_path:
                logger.error(f"[ML_ENGINE] No se encontró modelo sklearn en {self.model_path}")
                return False
            
            # Cargar modelo
            self.sklearn_model = joblib.load(sklearn_path)
            
            # Validar con predicción de prueba
            test_input = np.random.randn(1, len(self.feature_columns) or 81)
            try:
                _ = self.sklearn_model.predict(test_input)
                logger.info(f"[ML_ENGINE] ✅ Modelo sklearn validado: {sklearn_path.name}")
                return True
            except Exception as e:
                logger.error(f"[ML_ENGINE] Modelo sklearn no válido: {e}")
                self.sklearn_model = None
                return False
            
        except ImportError:
            logger.error("[ML_ENGINE] joblib no está instalado")
            return False
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error cargando sklearn: {e}")
            self.sklearn_model = None
            return False
    
    def _load_label_classes(self):
        """Carga las clases de etiquetas"""
        try:
            classes_files = [
                self.models_config.get('label_classes', ''),
                'label_classes.json'
            ]
            
            for classes_file in classes_files:
                if not classes_file:
                    continue
                    
                path = self.model_path / classes_file
                if path.exists():
                    with open(path, 'r', encoding='utf-8') as f:
                        self.label_classes = json.load(f)
                        logger.info(f"[ML_ENGINE] Clases cargadas: {self.label_classes}")
                        return
            
            # Clases por defecto
            self.label_classes = ["Benign", "Keylogger"]
            logger.warning("[ML_ENGINE] Usando clases por defecto: Benign, Keylogger")
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error cargando clases: {e}")
            self.label_classes = ["Benign", "Keylogger"]
    
    def _load_feature_metadata(self):
        """Carga metadatos de características"""
        try:
            metadata_files = [
                self.models_config.get('metadata', ''),
                'onnx_metadata_large_20250918_112840.json',
                'metadata.json'
            ]
            
            for metadata_file in metadata_files:
                if not metadata_file:
                    continue
                    
                path = self.model_path / metadata_file
                if path.exists():
                    with open(path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                        self.feature_columns = metadata.get('feature_names', metadata.get('feature_columns', []))
                        logger.info(f"[ML_ENGINE] Metadatos cargados: {len(self.feature_columns)} características")
                        return
            
            logger.warning("[ML_ENGINE] No se encontraron metadatos, usando configuración por defecto")
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error cargando metadatos: {e}")
    
    def predict(self, features: np.ndarray, async_prediction: bool = False) -> PredictionResult:
        """
        Realiza predicción usando el modelo cargado
        
        Args:
            features: Array de características (n_samples x n_features)
            async_prediction: Si True, ejecuta predicción de forma asíncrona
            
        Returns:
            PredictionResult: Resultado de la predicción
        """
        if async_prediction:
            return self._predict_async(features)
        else:
            return self._predict_sync(features)
    
    def _predict_sync(self, features: np.ndarray) -> PredictionResult:
        """Predicción síncrona"""
        try:
            if not self.is_ready():
                raise PredictionError("Motor ML no está listo")
            
            start_time = time.time()
            
            # Verificar cache si está habilitado
            if self.enable_caching:
                cache_key = self._generate_cache_key(features)
                if cache_key in self.prediction_cache:
                    self.stats['cache_hits'] += 1
                    return self.prediction_cache[cache_key]
                else:
                    self.stats['cache_misses'] += 1
            
            # Validar entrada
            features = self._validate_input(features)
            
            # Realizar predicción según tipo de modelo
            if self.current_model_type == 'ONNX':
                predictions, probabilities = self._predict_onnx(features)
            elif self.current_model_type == 'sklearn':
                predictions, probabilities = self._predict_sklearn(features)
            else:
                raise PredictionError(f"Tipo de modelo no soportado: {self.current_model_type}")
            
            prediction_time = time.time() - start_time
            
            # Calcular confidence scores
            confidence_scores = [prob if pred == "Keylogger" else 1.0 - prob for pred, prob in zip(predictions, probabilities)]
            
            # Crear resultado
            result = PredictionResult(
                predictions=predictions,
                probabilities=probabilities,
                prediction_time=prediction_time,
                model_type=self.current_model_type,
                confidence_scores=confidence_scores,
                metadata={
                    'feature_count': features.shape[1],
                    'samples_processed': features.shape[0],
                    'threshold_used': self.confidence_threshold
                }
            )
            
            # Actualizar estadísticas
            self._update_stats(len(predictions), prediction_time)
            
            # Guardar en cache
            if self.enable_caching:
                self._update_cache(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error en predicción: {e}")
            self.stats['errors'] += 1
            raise PredictionError(f"Error en predicción: {e}")
    
    def _predict_async(self, features: np.ndarray) -> PredictionResult:
        """Predicción asíncrona con timeout"""
        try:
            future = self.executor.submit(self._predict_sync, features)
            return future.result(timeout=self.prediction_timeout)
        except TimeoutError:
            logger.error(f"[ML_ENGINE] Timeout en predicción ({self.prediction_timeout}s)")
            self.stats['timeouts'] += 1
            raise PredictionError("Timeout en predicción")
    
    def _predict_onnx(self, features: np.ndarray) -> Tuple[List[str], List[float]]:
        """Predicción usando modelo ONNX"""
        try:
            # Convertir a float32 para ONNX
            features_float32 = features.astype(np.float32)
            
            # Ejecutar modelo
            outputs = self.onnx_model.run(self.output_names, {self.input_name: features_float32})
            
            # Procesar salidas
            predictions = []
            probabilities = []
            
            # El primer output suele ser las predicciones o logits
            if len(outputs) >= 1:
                predictions_output = outputs[0]
                
                # Procesar cada muestra
                for i in range(len(predictions_output)):
                    if len(predictions_output.shape) > 1:
                        # Multi-class output
                        class_probs = predictions_output[i]
                        class_idx = np.argmax(class_probs)
                        max_prob = float(np.max(class_probs))
                    else:
                        # Binary output
                        class_idx = int(predictions_output[i])
                        max_prob = 0.8  # Default probability
                    
                    # Mapear índice a nombre de clase
                    if class_idx < len(self.label_classes):
                        pred_class = self.label_classes[class_idx]
                    else:
                        pred_class = self.label_classes[0]  # Fallback
                    
                    predictions.append(pred_class)
                    probabilities.append(max_prob)
            
            return predictions, probabilities
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error en predicción ONNX: {e}")
            return [], []
    
    def _predict_sklearn(self, features: np.ndarray) -> Tuple[List[str], List[float]]:
        """Predicción usando modelo sklearn"""
        try:
            # Realizar predicción
            predictions = self.sklearn_model.predict(features)
            
            # Obtener probabilidades
            if hasattr(self.sklearn_model, 'predict_proba'):
                probabilities = self.sklearn_model.predict_proba(features)
                max_probs = [float(np.max(prob_row)) for prob_row in probabilities]
            else:
                # Usar confianza fija si no hay predict_proba
                max_probs = [0.8] * len(predictions)
            
            # Convertir predicciones a nombres de clase si es necesario
            if len(predictions) > 0 and isinstance(predictions[0], (int, np.integer)):
                predictions = [self.label_classes[pred] if pred < len(self.label_classes) else self.label_classes[0] for pred in predictions]
            
            return list(predictions), max_probs
            
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error en predicción sklearn: {e}")
            return [], []
    
    def _validate_input(self, features: np.ndarray) -> np.ndarray:
        """Valida y ajusta la entrada para predicción"""
        # Verificar que no está vacío
        if features.size == 0:
            raise ValueError("Array de características vacío")
        
        # Verificar dimensiones
        expected_features = len(self.feature_columns) or 81
        if features.shape[1] != expected_features:
            logger.warning(f"[ML_ENGINE] Ajustando características de {features.shape[1]} a {expected_features}")
            
            if features.shape[1] < expected_features:
                # Pad con ceros
                pad_width = ((0, 0), (0, expected_features - features.shape[1]))
                features = np.pad(features, pad_width, mode='constant', constant_values=0)
            else:
                # Truncar
                features = features[:, :expected_features]
        
        # Verificar tipos de datos
        if not np.issubdtype(features.dtype, np.number):
            features = features.astype(np.float64)
        
        # Verificar valores NaN/Inf
        if np.any(np.isnan(features)) or np.any(np.isinf(features)):
            logger.warning("[ML_ENGINE] Encontrados NaN/Inf, reemplazando con 0")
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        
        return features
    
    def _generate_cache_key(self, features: np.ndarray) -> str:
        """Genera clave de cache para las características"""
        # Hash simple basado en el contenido
        return str(hash(features.tobytes()))
    
    def _update_cache(self, cache_key: str, result: PredictionResult):
        """Actualiza el cache de predicciones"""
        if len(self.prediction_cache) >= self.cache_size:
            # Remover entrada más antigua (FIFO simple)
            oldest_key = next(iter(self.prediction_cache))
            del self.prediction_cache[oldest_key]
        
        self.prediction_cache[cache_key] = result
    
    def _update_stats(self, predictions_count: int, prediction_time: float):
        """Actualiza estadísticas del motor"""
        with self._lock:
            self.stats['predictions_made'] += predictions_count
            
            # Media móvil del tiempo de predicción
            if self.stats['avg_prediction_time'] == 0:
                self.stats['avg_prediction_time'] = prediction_time
            else:
                alpha = 0.1  # Factor de suavizado
                self.stats['avg_prediction_time'] = (
                    alpha * prediction_time + (1 - alpha) * self.stats['avg_prediction_time']
                )
    
    def is_ready(self) -> bool:
        """Verifica si el motor está listo para predicciones"""
        return (self.onnx_model is not None) or (self.sklearn_model is not None)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Obtiene información del modelo cargado"""
        info = {
            'model_type': self.current_model_type,
            'label_classes': self.label_classes,
            'feature_count': len(self.feature_columns),
            'confidence_threshold': self.confidence_threshold,
            'is_ready': self.is_ready()
        }
        
        if self.current_model_type == 'ONNX' and self.onnx_model:
            info['input_shape'] = getattr(self, 'input_shape', None)
            info['output_names'] = getattr(self, 'output_names', [])
        
        return info
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del motor"""
        return {
            **self.stats,
            **self.get_model_info(),
            'cache_enabled': self.enable_caching,
            'cache_size': len(self.prediction_cache) if self.prediction_cache else 0
        }
    
    def clear_cache(self):
        """Limpia el cache de predicciones"""
        if self.prediction_cache:
            self.prediction_cache.clear()
            logger.info("[ML_ENGINE] Cache de predicciones limpiado")
    
    def shutdown(self):
        """Cierra el motor ML limpiamente"""
        try:
            self.executor.shutdown(wait=True)
            self.clear_cache()
            logger.info("[ML_ENGINE] Motor ML cerrado correctamente")
        except Exception as e:
            logger.error(f"[ML_ENGINE] Error cerrando motor: {e}")


if __name__ == "__main__":
    # Test standalone del motor ML
    print("🧪 Testing ML Engine...")
    
    # Configuración de prueba
    test_config = {
        'ml_config': {
            'model_path': '../../../ANTIVIRUS_PRODUCTION/models',
            'use_onnx': True,
            'confidence_threshold': 0.8
        },
        'models': {
            'primary_onnx': 'modelo_keylogger_from_datos.onnx',
            'fallback_sklearn': 'rf_large_model_20250918_112442.pkl'
        }
    }
    
    try:
        engine = MLEngine(test_config)
        
        if engine.is_ready():
            print(f"✅ Motor inicializado: {engine.current_model_type}")
            
            # Test de predicción
            test_features = np.random.randn(2, 81)
            result = engine.predict(test_features)
            
            print(f"🎯 Predicciones: {result.predictions}")
            print(f"📊 Probabilidades: {result.probabilities}")
            print(f"⏱️ Tiempo: {result.prediction_time:.3f}s")
            print(f"📈 Stats: {engine.get_stats()}")
        else:
            print("❌ Motor no está listo")
            
    except Exception as e:
        print(f"❌ Error: {e}")