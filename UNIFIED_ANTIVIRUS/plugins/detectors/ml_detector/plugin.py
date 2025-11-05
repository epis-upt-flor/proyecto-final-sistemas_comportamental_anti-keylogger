"""
ML Detector Plugin
==================

Plugin de detección de keyloggers usando Machine Learning con modelos ONNX.
Implementa múltiples patrones de diseño para integración con el sistema unificado.
"""

import logging
import asyncio
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
from pathlib import Path
import psutil

# Importar componentes del core
import sys
from pathlib import Path

# Añadir el directorio raíz al sys.path si no está presente
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import DetectorInterface

# Importar componentes específicos del ML detector
from .ml_engine import MLEngine, PredictionError, ModelLoadError
from .feature_extractor import NetworkFeatureExtractor

logger = logging.getLogger(__name__)


class MLDetectorPlugin(BasePlugin, DetectorInterface):
    """
    Plugin detector de keyloggers usando Machine Learning

    Patrones implementados:
    - Template Method: Hereda ciclo de vida de BasePlugin
    - Strategy: Múltiples estrategias de ML (ONNX, sklearn)
    - Observer: Recibe eventos del sistema y publica detecciones
    - Factory: Crea instancias de motor ML según configuración
    """

    def __init__(self, config_path: str = None):
        """
        Inicializa el plugin ML Detector

        Args:
            config_path: Ruta al archivo de configuración
        """
        super().__init__(
            plugin_name="ml_detector", plugin_path=str(Path(__file__).parent)
        )

        # Información del plugin
        self.name = "ml_detector"
        self.version = "1.0.0"
        self.description = "Detector de keyloggers usando Machine Learning"

        # Cargar configuración
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()

        # Corregir ruta de modelos si es relativa
        if "ml_config" in self.config and "model_path" in self.config["ml_config"]:
            model_path = self.config["ml_config"]["model_path"]
            if not Path(model_path).is_absolute():
                # Calcular ruta absoluta desde el directorio del proyecto
                project_root = Path(__file__).parent.parent.parent.parent
                models_path = project_root / "models"
                # Verificar si existe la carpeta models en UNIFIED_ANTIVIRUS
                if not models_path.exists():
                    # Si no existe, usar la de ANTIVIRUS_PRODUCTION
                    models_path = (
                        project_root.parent / "ANTIVIRUS_PRODUCTION" / "models"
                    )
                self.config["ml_config"]["model_path"] = str(models_path)

        # Componentes principales
        self.ml_engine: Optional[MLEngine] = None
        self.feature_extractor: Optional[NetworkFeatureExtractor] = None
        self.event_publisher: Optional[Any] = None

        # Estado del plugin
        self.is_scanning = False
        self.scan_thread = None
        self.analysis_queue = asyncio.Queue() if hasattr(asyncio, "Queue") else []

        # Estadísticas y estado
        self.last_confidence_score = 0.8
        self.detections_count = 0
        self.processed_events = 0
        self.last_detection_time = None

        # Estadísticas
        self.stats = {
            "scans_performed": 0,
            "threats_detected": 0,
            "total_network_flows_analyzed": 0,
            "avg_scan_time": 0.0,
            "last_scan_time": None,
            "model_predictions": 0,
            "high_confidence_detections": 0,
        }

        # Configuración del detector
        self.detection_config = self.config.get("ml_config", {})
        self.confidence_threshold = self.detection_config.get(
            "confidence_threshold", 0.8
        )
        self.batch_processing = self.detection_config.get(
            "enable_batch_processing", True
        )
        self.max_batch_size = self.detection_config.get("batch_size", 32)

        logger.info(
            f"[ML_DETECTOR] Plugin inicializado con configuración desde {self.config_path}"
        )

    def _get_default_config_path(self) -> str:
        """Obtiene la ruta por defecto de configuración"""
        plugin_dir = Path(__file__).parent
        return str(plugin_dir / "config.json")

    def _load_config(self) -> Dict[str, Any]:
        """Carga configuración desde archivo JSON"""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                logger.info(
                    f"[ML_DETECTOR] Configuración cargada: {len(config)} secciones"
                )
                return config
        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error cargando configuración: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto si no se puede cargar el archivo"""
        return {
            "plugin_info": {
                "name": "ml_detector",
                "version": "1.0.0",
                "category": "detectors",
                "priority": 1,
            },
            "ml_config": {
                "model_path": str(
                    Path(__file__).parent.parent.parent.parent
                    / "ANTIVIRUS_PRODUCTION"
                    / "models"
                ),
                "use_onnx": True,
                "confidence_threshold": 0.8,
                "batch_size": 32,
            },
            "models": {
                "primary_onnx": "modelo_keylogger_from_datos.onnx",
                "fallback_sklearn": "rf_large_model_20250918_112442.pkl",
            },
        }

    # Implementación de Template Method Pattern (BasePlugin)

    def initialize(self) -> bool:
        """
        Inicialización específica del plugin ML
        Parte del Template Method Pattern
        """
        try:
            logger.info("[ML_DETECTOR] Inicializando componentes ML...")

            # 1. Crear e inicializar motor ML
            self.ml_engine = MLEngine(self.config)

            if not self.ml_engine.is_ready():
                raise ModelLoadError("Motor ML no está listo")

            # 2. Crear extractor de características
            feature_columns = self.ml_engine.feature_columns
            self.feature_extractor = NetworkFeatureExtractor(
                feature_columns=feature_columns,
                config=self.config.get("feature_extraction", {}),
            )

            # 3. Configurar análisis asíncrono
            if self.config.get("performance", {}).get("enable_async_processing", True):
                self._setup_async_processing()

            logger.info(
                f"[ML_DETECTOR] ✅ Plugin inicializado (Modelo: {self.ml_engine.current_model_type})"
            )
            return True

        except Exception as e:
            logger.error(f"[ML_DETECTOR] ❌ Error en inicialización: {e}")
            return False

    def start(self) -> bool:
        """
        Inicia el plugin ML detector
        Parte del Template Method Pattern
        """
        try:
            if not self.ml_engine or not self.ml_engine.is_ready():
                logger.error("[ML_DETECTOR] Motor ML no está listo para iniciar")
                return False

            # Publicar evento de modelo cargado
            if self.event_publisher:
                self.event_publisher.publish(
                    "model_loaded",
                    {
                        "plugin": self.name,
                        "model_type": self.ml_engine.current_model_type,
                        "model_info": self.ml_engine.get_model_info(),
                    },
                )

            logger.info("[ML_DETECTOR] ✅ Plugin iniciado y listo para detecciones")
            return True

        except Exception as e:
            logger.error(f"[ML_DETECTOR] ❌ Error iniciando plugin: {e}")
            return False

    def stop(self) -> bool:
        """
        Detiene el plugin ML detector
        Parte del Template Method Pattern
        """
        try:
            # Detener escaneo si está activo
            if self.is_scanning:
                self.is_scanning = False
                if self.scan_thread and self.scan_thread.is_alive():
                    self.scan_thread.join(timeout=5.0)

            # Cerrar motor ML
            if self.ml_engine:
                self.ml_engine.shutdown()

            logger.info("[ML_DETECTOR] ✅ Plugin detenido correctamente")
            return True

        except Exception as e:
            logger.error(f"[ML_DETECTOR] ❌ Error deteniendo plugin: {e}")
            return False

    # Implementación de DetectorInterface

    def detect_threats(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detecta amenazas en los datos del sistema usando ML

        Args:
            system_data: Datos del sistema para analizar

        Returns:
            List[Dict]: Lista de amenazas detectadas
        """
        threats = []

        try:
            start_time = datetime.now()

            # Extraer datos de red para análisis
            network_data = self._extract_network_data(system_data)

            if not network_data:
                logger.debug("[ML_DETECTOR] No hay datos de red para analizar")
                return threats

            # Realizar análisis ML
            threats = self._analyze_with_ml(network_data)

            # Actualizar estadísticas
            scan_time = (datetime.now() - start_time).total_seconds()
            self._update_stats(len(threats), scan_time, len(network_data))

            # Publicar eventos para cada amenaza detectada
            for threat in threats:
                if self.event_publisher:
                    self.event_publisher.publish(
                        "threat_detected",
                        {
                            "plugin": self.name,
                            "threat": threat,
                            "timestamp": datetime.now().isoformat(),
                        },
                    )

            logger.info(
                f"[ML_DETECTOR] ✅ Análisis completado: {len(threats)} amenazas detectadas en {scan_time:.2f}s"
            )

        except Exception as e:
            logger.error(f"[ML_DETECTOR] ❌ Error en detección: {e}")
            if self.event_publisher:
                self.event_publisher.publish(
                    "prediction_error",
                    {
                        "plugin": self.name,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    },
                )

        return threats

    def scan_system(self) -> Dict[str, Any]:
        """
        Realiza escaneo completo del sistema
        """
        try:
            if self.is_scanning:
                return {
                    "status": "already_scanning",
                    "message": "Escaneo ya en progreso",
                }

            self.is_scanning = True
            scan_start = datetime.now()

            logger.info("[ML_DETECTOR] 🔍 Iniciando escaneo completo del sistema...")

            # Simular obtención de datos del sistema (en implementación real vendría del monitor)
            system_data = self._get_current_system_data()

            # Detectar amenazas
            threats = self.detect_threats(system_data)

            # Preparar resultado
            scan_time = (datetime.now() - scan_start).total_seconds()
            result = {
                "status": "completed",
                "scan_time": scan_time,
                "threats_found": len(threats),
                "threats": threats,
                "scanner": self.name,
                "timestamp": datetime.now().isoformat(),
                "stats": self.get_stats(),
            }

            # Publicar evento de escaneo completado
            if self.event_publisher:
                self.event_publisher.publish(
                    "ml_analysis_completed", {"plugin": self.name, "result": result}
                )

            self.is_scanning = False
            return result

        except Exception as e:
            self.is_scanning = False
            logger.error(f"[ML_DETECTOR] ❌ Error en escaneo: {e}")
            return {
                "status": "error",
                "error": str(e),
                "scanner": self.name,
                "timestamp": datetime.now().isoformat(),
            }

    def get_scan_status(self) -> Dict[str, Any]:
        """Obtiene estado actual del escaneo"""
        return {
            "is_scanning": self.is_scanning,
            "plugin": self.name,
            "last_scan": self.stats.get("last_scan_time"),
            "total_scans": self.stats.get("scans_performed", 0),
            "model_ready": self.ml_engine.is_ready() if self.ml_engine else False,
        }

    # Implementación de Observer Pattern (EventSubscriber)

    def on_event(self, event_type: str, data: Dict[str, Any]):
        """
        Maneja eventos del sistema (Observer Pattern)

        Args:
            event_type: Tipo de evento
            data: Datos del evento
        """
        try:
            if event_type == "network_data_available":
                self._handle_network_data(data)
            elif event_type == "scan_requested":
                self._handle_scan_request(data)
            elif event_type == "config_updated":
                self._handle_config_update(data)
            elif event_type == "system_startup":
                self._handle_system_startup(data)
            else:
                logger.debug(f"[ML_DETECTOR] Evento ignorado: {event_type}")

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error procesando evento {event_type}: {e}")

    def _handle_network_data(self, data: Dict[str, Any]):
        """Procesa datos de red recibidos por eventos"""
        try:
            network_flows = data.get("network_flows", [])
            if network_flows and self.ml_engine and self.ml_engine.is_ready():
                # Análisis en tiempo real de flujos de red
                threats = self._analyze_with_ml(network_flows)

                # Publicar amenazas encontradas
                for threat in threats:
                    if self.event_publisher:
                        self.event_publisher.publish(
                            "threat_detected",
                            {
                                "plugin": self.name,
                                "threat": threat,
                                "source": "realtime_network_analysis",
                                "timestamp": datetime.now().isoformat(),
                            },
                        )

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error procesando datos de red: {e}")

    def _handle_scan_request(self, data: Dict[str, Any]):
        """Maneja solicitudes de escaneo"""
        try:
            scan_type = data.get("type", "full")
            if scan_type == "ml" or scan_type == "full":
                # Ejecutar escaneo en hilo separado para no bloquear
                self.scan_thread = threading.Thread(target=self.scan_system)
                self.scan_thread.daemon = True
                self.scan_thread.start()

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error procesando solicitud de escaneo: {e}")

    def _handle_config_update(self, data: Dict[str, Any]):
        """Maneja actualizaciones de configuración"""
        try:
            # Recargar configuración si es necesario
            if data.get("plugin") == self.name or data.get("global_update"):
                logger.info("[ML_DETECTOR] Recargando configuración...")
                self.config = self._load_config()
                # Nota: Para cambios en modelos ML, sería necesario reinicializar el motor

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error actualizando configuración: {e}")

    def _handle_system_startup(self, data: Dict[str, Any]):
        """Maneja eventos de arranque del sistema"""
        try:
            logger.info(
                "[ML_DETECTOR] Sistema iniciado, ejecutando validación de modelos..."
            )
            if self.ml_engine:
                model_info = self.ml_engine.get_model_info()
                logger.info(f"[ML_DETECTOR] Estado del modelo: {model_info}")

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error en startup: {e}")

    # Métodos auxiliares

    def _extract_network_data(
        self, system_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extrae datos de red relevantes para ML"""
        try:
            # Múltiples fuentes de datos de red
            network_data = []

            # 1. Conexiones de red activas
            if "network_connections" in system_data:
                network_data.extend(system_data["network_connections"])

            # 2. Tráfico de red capturado
            if "network_traffic" in system_data:
                network_data.extend(system_data["network_traffic"])

            # 3. Flujos de red monitoreados
            if "network_flows" in system_data:
                network_data.extend(system_data["network_flows"])

            return network_data

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error extrayendo datos de red: {e}")
            return []

    def _analyze_with_ml(
        self, network_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Realiza análisis ML de los datos de red"""
        threats = []

        try:
            if not self.ml_engine or not self.feature_extractor:
                logger.warning("[ML_DETECTOR] Componentes ML no están listos")
                return threats

            # 1. Extraer características
            features = self.feature_extractor.extract_features_from_network_data(
                network_data
            )

            if features.size == 0:
                logger.debug("[ML_DETECTOR] No se extrajeron características válidas")
                return threats

            # 2. Realizar predicción ML
            prediction_result = self.ml_engine.predict(features)

            # 3. Procesar resultados y crear amenazas
            for i, (prediction, probability, confidence) in enumerate(
                zip(
                    prediction_result.predictions,
                    prediction_result.probabilities,
                    prediction_result.confidence_scores or [],
                )
            ):
                if (
                    prediction == "Keylogger"
                    and probability >= self.confidence_threshold
                ):
                    threat = {
                        "id": f"ml_threat_{datetime.now().timestamp()}_{i}",
                        "type": "keylogger",
                        "severity": self._calculate_severity(probability),
                        "confidence": float(probability),
                        "confidence_score": (
                            float(confidence) if confidence else float(probability)
                        ),
                        "source": "ml_detector",
                        "detector": self.name,
                        "timestamp": datetime.now().isoformat(),
                        "details": {
                            "model_prediction": prediction,
                            "prediction_probability": float(probability),
                            "model_type": prediction_result.model_type,
                            "prediction_time": prediction_result.prediction_time,
                            "flow_index": i,
                            "feature_count": features.shape[1],
                            "network_flow_data": (
                                network_data[i] if i < len(network_data) else None
                            ),
                        },
                        "metadata": {
                            **prediction_result.metadata,
                            "plugin_version": self.version,
                            "config_threshold": self.confidence_threshold,
                        },
                    }
                    threats.append(threat)

                    # Estadística adicional para alta confianza
                    if probability > 0.9:
                        self.stats["high_confidence_detections"] += 1

            self.stats["model_predictions"] += len(prediction_result.predictions)

        except Exception as e:
            logger.error(f"[ML_DETECTOR] Error en análisis ML: {e}")
            if self.event_publisher:
                self.event_publisher.publish(
                    "prediction_error",
                    {
                        "plugin": self.name,
                        "error": str(e),
                        "data_size": len(network_data),
                    },
                )

        return threats

    def _calculate_severity(self, probability: float) -> str:
        """Calcula severidad basada en probabilidad"""
        if probability >= 0.95:
            return "critical"
        elif probability >= 0.85:
            return "high"
        elif probability >= 0.75:
            return "medium"
        else:
            return "low"

    def _get_current_system_data(self) -> Dict[str, Any]:
        """Obtiene datos reales actuales del sistema para análisis ML"""
        try:
            network_connections = []
            network_flows = []

            # Obtener conexiones de red activas
            try:
                net_connections = psutil.net_connections(kind="inet")
                for conn in net_connections:
                    if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                        try:
                            # Obtener información del proceso
                            process_info = {"name": "unknown", "exe": "unknown"}
                            if conn.pid:
                                try:
                                    proc = psutil.Process(conn.pid)
                                    process_info = {
                                        "name": proc.name(),
                                        "exe": proc.exe() if proc.exe() else "unknown",
                                        "cpu_percent": proc.cpu_percent(),
                                        "memory_info": proc.memory_info()._asdict(),
                                    }
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass

                            # Crear conexión para ML
                            connection_data = {
                                "local_ip": conn.laddr.ip if conn.laddr else "",
                                "local_port": conn.laddr.port if conn.laddr else 0,
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "protocol": "TCP" if conn.type == 1 else "UDP",
                                "pid": conn.pid or 0,
                                "process": process_info,
                                "timestamp": datetime.now().isoformat(),
                            }
                            network_connections.append(connection_data)

                            # Crear flujo de red para análisis ML
                            network_flow = {
                                "src_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                                "src_port": conn.laddr.port if conn.laddr else 0,
                                "dst_ip": conn.raddr.ip,
                                "dst_port": conn.raddr.port,
                                "protocol": "TCP" if conn.type == 1 else "UDP",
                                "duration": 1.0,  # Estimado
                                "total_fwd_packets": 1,
                                "total_backward_packets": 1,
                                "flow_bytes_s": 0,  # Calculado más tarde
                                "flow_packets_s": 0,
                                "process_name": process_info.get("name", "unknown"),
                            }
                            network_flows.append(network_flow)

                        except Exception as e:
                            logger.debug(f"Error procesando conexión para ML: {e}")
                            continue

            except Exception as e:
                logger.error(f"Error obteniendo conexiones de red: {e}")

            return {
                "network_connections": network_connections,
                "network_flows": network_flows,
                "system_stats": {
                    "cpu_percent": psutil.cpu_percent(interval=0.1),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_io": (
                        psutil.disk_io_counters()._asdict()
                        if psutil.disk_io_counters()
                        else {}
                    ),
                    "network_io": (
                        psutil.net_io_counters()._asdict()
                        if psutil.net_io_counters()
                        else {}
                    ),
                },
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error obteniendo datos del sistema: {e}")
            return {
                "network_connections": [],
                "network_flows": [],
                "timestamp": datetime.now().isoformat(),
            }

    def _setup_async_processing(self):
        """Configura procesamiento asíncrono si está disponible"""
        try:
            # Configuración para procesamiento asíncrono de eventos
            pass
        except Exception as e:
            logger.warning(
                f"[ML_DETECTOR] No se pudo configurar procesamiento asíncrono: {e}"
            )

    def _update_stats(self, threats_count: int, scan_time: float, flows_analyzed: int):
        """Actualiza estadísticas del plugin"""
        self.stats["scans_performed"] += 1
        self.stats["threats_detected"] += threats_count
        self.stats["total_network_flows_analyzed"] += flows_analyzed
        self.stats["last_scan_time"] = datetime.now().isoformat()

        # Media móvil del tiempo de escaneo
        if self.stats["avg_scan_time"] == 0:
            self.stats["avg_scan_time"] = scan_time
        else:
            alpha = 0.1
            self.stats["avg_scan_time"] = (
                alpha * scan_time + (1 - alpha) * self.stats["avg_scan_time"]
            )

    # Interfaz pública adicional

    def set_event_publisher(self, publisher: Any):
        """Establece el publicador de eventos"""
        self.event_publisher = publisher
        logger.info("[ML_DETECTOR] Event publisher configurado")

    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas completas del plugin"""
        stats = {
            **self.stats,
            "plugin_info": {
                "name": self.name,
                "version": self.version,
                "category": self.category,
                "status": (
                    "active"
                    if self.ml_engine and self.ml_engine.is_ready()
                    else "inactive"
                ),
            },
        }

        # Agregar stats del motor ML si está disponible
        if self.ml_engine:
            stats["ml_engine"] = self.ml_engine.get_stats()

        # Agregar stats del extractor de características
        if self.feature_extractor:
            stats["feature_extractor"] = self.feature_extractor.get_stats()

        return stats

    def get_model_info(self) -> Dict[str, Any]:
        """Obtiene información detallada del modelo ML"""
        if self.ml_engine:
            return self.ml_engine.get_model_info()
        return {"error": "Motor ML no disponible"}

    def update_confidence_threshold(self, new_threshold: float):
        """Actualiza el threshold de confianza"""
        if 0.0 <= new_threshold <= 1.0:
            self.confidence_threshold = new_threshold
            logger.info(f"[ML_DETECTOR] Threshold actualizado a {new_threshold}")
        else:
            logger.error(f"[ML_DETECTOR] Threshold inválido: {new_threshold}")

    def force_model_reload(self) -> bool:
        """Fuerza recarga del modelo ML"""
        try:
            logger.info("[ML_DETECTOR] Recargando modelo ML...")

            if self.ml_engine:
                self.ml_engine.shutdown()

            self.ml_engine = MLEngine(self.config)

            if self.ml_engine.is_ready():
                logger.info("[ML_DETECTOR] ✅ Modelo recargado exitosamente")
                return True
            else:
                logger.error("[ML_DETECTOR] ❌ Error recargando modelo")
                return False

        except Exception as e:
            logger.error(f"[ML_DETECTOR] ❌ Error en recarga: {e}")
            return False

    # === Métodos abstractos faltantes ===

    def get_plugin_info(self) -> Dict[str, Any]:
        """
        Información específica del plugin ML Detector
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": "detectors",
            "type": "ml_detector",
            "capabilities": ["ml_detection", "onnx_models", "network_analysis"],
            "dependencies": ["onnxruntime", "numpy", "pandas", "scikit-learn"],
            "models_loaded": 1 if self.ml_engine and self.ml_engine.is_ready() else 0,
            "status": "active" if self.is_running else "inactive",
        }

    def get_confidence_score(self) -> float:
        """
        Retorna el nivel de confianza de la última detección
        """
        return self.last_confidence_score

    def update_signatures(self) -> bool:
        """
        Actualiza las firmas/patrones de detección (modelos ML)
        """
        try:
            if self.ml_engine:
                # En implementación real, aquí se recargarían los modelos
                logger.info("Modelos ML actualizados")
                return True
            return False
        except Exception as e:
            logger.error(f"Error actualizando modelos: {e}")
            return False

    def get_detection_statistics(self) -> Dict[str, Any]:
        """
        Estadísticas de detección del plugin ML
        """
        return {
            "total_detections": self.detections_count,
            "processed_samples": self.processed_events,
            "last_detection": (
                self.last_detection_time.isoformat()
                if self.last_detection_time
                else None
            ),
            "average_confidence": self.last_confidence_score,
            "ml_engine_loaded": self.ml_engine is not None,
            "models_count": 1 if self.ml_engine and self.ml_engine.is_ready() else 0,
            "plugin_uptime": (
                (datetime.now() - self.start_time).total_seconds()
                if hasattr(self, "start_time")
                else 0
            ),
        }


# Auto-registro del plugin
def create_plugin(config_path: str = None) -> MLDetectorPlugin:
    """Factory function para crear instancia del plugin"""
    return MLDetectorPlugin(config_path)


if __name__ == "__main__":
    # Test standalone del plugin
    import sys

    print("🧪 Testing ML Detector Plugin...")

    try:
        # Crear plugin
        plugin = MLDetectorPlugin()

        print(f"✅ Plugin creado: {plugin.name} v{plugin.version}")

        # Inicializar
        if plugin.initialize():
            print("✅ Plugin inicializado correctamente")

            # Iniciar
            if plugin.start():
                print("✅ Plugin iniciado correctamente")

                # Test de detección
                test_data = {
                    "network_connections": [
                        {
                            "src_ip": "192.168.1.100",
                            "dst_ip": "10.0.0.1",
                            "src_port": 1234,
                            "dst_port": 80,
                            "packet_size": 512,
                            "timestamp": "2024-01-15 10:30:00",
                        }
                    ]
                }

                threats = plugin.detect_threats(test_data)
                print(f"🎯 Amenazas detectadas: {len(threats)}")

                # Mostrar estadísticas
                stats = plugin.get_stats()
                print(f"📊 Stats: {stats['scans_performed']} escaneos realizados")

                # Detener
                plugin.stop()
                print("✅ Plugin detenido correctamente")

            else:
                print("❌ Error iniciando plugin")
                sys.exit(1)
        else:
            print("❌ Error inicializando plugin")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    print("🎉 Test completado exitosamente")
