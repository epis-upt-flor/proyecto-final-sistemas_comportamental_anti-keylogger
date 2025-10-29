"""
Feature Extractor para ML Detector
=================================

Extractor especializado de características de red para detección de keyloggers.
Convierte datos de red brutos en vectores de características para ML.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class NetworkFeatureExtractor:
    """
    Extractor de características de red para ML
    
    Implementa Strategy Pattern para diferentes tipos de extracción
    """
    
    def __init__(self, feature_columns: List[str] = None, config: Dict = None):
        """
        Args:
            feature_columns: Lista de nombres de características esperadas
            config: Configuración del extractor
        """
        self.feature_columns = feature_columns or self._get_default_features()
        self.config = config or {}
        self.extraction_stats = {
            'flows_processed': 0,
            'features_extracted': 0,
            'extraction_errors': 0,
            'avg_extraction_time': 0.0
        }
        
        logger.info(f"[FEATURES] NetworkFeatureExtractor inicializado con {len(self.feature_columns)} características")
    
    def _get_default_features(self) -> List[str]:
        """Características por defecto basadas en el dataset CIC-IDS2017"""
        return [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
            'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
            'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
            'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
            'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
            'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
            'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
            'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
            'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
            'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
            'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean',
            'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
            'Idle Max', 'Idle Min'
        ]
    
    def extract_features_from_network_data(self, network_data: List[Dict]) -> np.ndarray:
        """
        Extrae características de datos de red para ML
        
        Args:
            network_data: Lista de diccionarios con datos de conexiones de red
            
        Returns:
            np.ndarray: Array 2D con características extraídas (flows x features)
        """
        try:
            start_time = datetime.now()
            
            # Validar entrada
            if not network_data or len(network_data) == 0:
                logger.debug("[FEATURES] Sin datos de red, retornando array vacío")
                return np.array([]).reshape(0, len(self.feature_columns))
            
            # Convertir a DataFrame para facilitar procesamiento
            df = pd.DataFrame(network_data)
            features_list = []
            
            # Strategy Pattern: Elegir método de extracción según datos disponibles
            if self._has_flow_data(df):
                features_list = self._extract_flow_based_features(df)
            elif self._has_packet_data(df):
                features_list = self._extract_packet_based_features(df)
            else:
                features_list = self._extract_basic_features(df)
            
            # Convertir a numpy array
            features_array = np.array(features_list) if features_list else np.array([]).reshape(0, len(self.feature_columns))
            
            # Validar dimensiones
            if features_array.size > 0:
                features_array = self._validate_feature_dimensions(features_array)
            
            # Actualizar estadísticas
            self._update_stats(len(features_list), start_time)
            
            logger.debug(f"[FEATURES] Extraídas {features_array.shape[0]} filas con {features_array.shape[1]} características")
            return features_array
            
        except Exception as e:
            logger.error(f"[ERROR] Error extrayendo características: {e}")
            self.extraction_stats['extraction_errors'] += 1
            return np.array([]).reshape(0, len(self.feature_columns))
    
    def _has_flow_data(self, df: pd.DataFrame) -> bool:
        """Verifica si los datos contienen información de flujos completos"""
        required_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
        return all(col in df.columns for col in required_columns)
    
    def _has_packet_data(self, df: pd.DataFrame) -> bool:
        """Verifica si los datos contienen información de paquetes individuales"""
        packet_columns = ['packet_size', 'timestamp', 'protocol']
        return any(col in df.columns for col in packet_columns)
    
    def _extract_flow_based_features(self, df: pd.DataFrame) -> List[List[float]]:
        """Extrae características agrupando por flujos de red"""
        features_list = []
        
        try:
            # Agrupar por flujo (conexión única)
            flow_groups = df.groupby(['src_ip', 'dst_ip', 'src_port', 'dst_port'])
            
            for flow_key, flow_group in flow_groups:
                flow_features = self._calculate_flow_features(flow_group)
                features_list.append(flow_features)
                
        except Exception as e:
            logger.error(f"[ERROR] Error en extracción basada en flujos: {e}")
            
        return features_list
    
    def _extract_packet_based_features(self, df: pd.DataFrame) -> List[List[float]]:
        """Extrae características de datos de paquetes individuales"""
        try:
            # Tratar todos los paquetes como un solo flujo agregado
            aggregated_features = self._calculate_flow_features(df)
            return [aggregated_features]
            
        except Exception as e:
            logger.error(f"[ERROR] Error en extracción basada en paquetes: {e}")
            return []
    
    def _extract_basic_features(self, df: pd.DataFrame) -> List[List[float]]:
        """Extrae características básicas cuando los datos son limitados"""
        try:
            # Generar características básicas con valores por defecto
            basic_features = self._generate_default_features(df)
            return [basic_features]
            
        except Exception as e:
            logger.error(f"[ERROR] Error en extracción básica: {e}")
            return []
    
    def _calculate_flow_features(self, flow_data: pd.DataFrame) -> List[float]:
        """
        Calcula las 81 características estándar para un flujo
        
        Args:
            flow_data: DataFrame con datos del flujo
            
        Returns:
            List[float]: Vector de características
        """
        features = []
        
        try:
            # 1. Duración del flujo
            flow_duration = self._calculate_flow_duration(flow_data)
            features.append(flow_duration)
            
            # 2-3. Conteo de paquetes forward/backward
            fwd_packets, bwd_packets = self._calculate_packet_counts(flow_data)
            features.extend([fwd_packets, bwd_packets])
            
            # 4-5. Longitud total de paquetes forward/backward
            fwd_bytes, bwd_bytes = self._calculate_total_bytes(flow_data)
            features.extend([fwd_bytes, bwd_bytes])
            
            # 6-13. Estadísticas de longitud de paquetes
            fwd_stats = self._calculate_packet_length_stats(flow_data, direction='fwd')
            bwd_stats = self._calculate_packet_length_stats(flow_data, direction='bwd')
            features.extend(fwd_stats)  # Max, Min, Mean, Std
            features.extend(bwd_stats)  # Max, Min, Mean, Std
            
            # 14-15. Flow rates (bytes/s, packets/s)
            flow_bytes_per_sec = (fwd_bytes + bwd_bytes) / max(flow_duration, 1)
            flow_packets_per_sec = (fwd_packets + bwd_packets) / max(flow_duration, 1)
            features.extend([flow_bytes_per_sec, flow_packets_per_sec])
            
            # 16-19. Inter-Arrival Time (IAT) del flujo
            flow_iat_stats = self._calculate_iat_stats(flow_data)
            features.extend(flow_iat_stats)  # Mean, Std, Max, Min
            
            # 20-28. IAT Forward/Backward
            fwd_iat_stats = self._calculate_direction_iat_stats(flow_data, 'fwd')
            bwd_iat_stats = self._calculate_direction_iat_stats(flow_data, 'bwd')
            features.extend(fwd_iat_stats)  # Total, Mean, Std, Max, Min
            features.extend(bwd_iat_stats)  # Total, Mean, Std, Max, Min
            
            # 29-36. Flags TCP
            tcp_flags = self._calculate_tcp_flags(flow_data)
            features.extend(tcp_flags)  # Fwd PSH, Bwd PSH, Fwd URG, Bwd URG, Fwd Header, Bwd Header, Fwd Packets/s, Bwd Packets/s
            
            # 37-42. Estadísticas generales de paquetes
            packet_stats = self._calculate_general_packet_stats(flow_data)
            features.extend(packet_stats)  # Min, Max, Mean, Std, Variance
            
            # 43-50. Conteo de flags TCP
            flag_counts = self._calculate_flag_counts(flow_data)
            features.extend(flag_counts)  # FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
            
            # 51-53. Ratios y tamaños promedio
            down_up_ratio = bwd_bytes / max(fwd_bytes, 1)
            avg_packet_size = (fwd_bytes + bwd_bytes) / max(fwd_packets + bwd_packets, 1)
            avg_fwd_segment = fwd_bytes / max(fwd_packets, 1)
            avg_bwd_segment = bwd_bytes / max(bwd_packets, 1)
            features.extend([down_up_ratio, avg_packet_size, avg_fwd_segment, avg_bwd_segment])
            
            # 54. Header length duplicado (compatibilidad)
            features.append(features[33] if len(features) > 33 else 0)  # Fwd Header Length.1
            
            # 55-60. Bulk transfer rates
            bulk_stats = self._calculate_bulk_stats(flow_data)
            features.extend(bulk_stats)  # Fwd/Bwd Avg Bytes/Bulk, Packets/Bulk, Bulk Rate
            
            # 61-64. Subflow statistics
            subflow_stats = [fwd_packets, fwd_bytes, bwd_packets, bwd_bytes]
            features.extend(subflow_stats)
            
            # 65-68. Window sizes y otros
            window_stats = self._calculate_window_stats(flow_data)
            features.extend(window_stats)  # Init_Win_bytes_forward, backward, act_data_pkt_fwd, min_seg_size_forward
            
            # 69-76. Active/Idle times
            active_idle_stats = self._calculate_active_idle_stats(flow_data)
            features.extend(active_idle_stats)  # Active Mean, Std, Max, Min, Idle Mean, Std, Max, Min
            
        except Exception as e:
            logger.error(f"[ERROR] Error calculando características del flujo: {e}")
            # Rellenar con ceros en caso de error
            features = [0.0] * len(self.feature_columns)
        
        # Asegurar que tenemos exactamente el número correcto de características
        while len(features) < len(self.feature_columns):
            features.append(0.0)
        
        features = features[:len(self.feature_columns)]
        
        return features
    
    def _calculate_flow_duration(self, flow_data: pd.DataFrame) -> float:
        """Calcula la duración del flujo en segundos"""
        try:
            if 'timestamp' not in flow_data.columns or len(flow_data) < 2:
                return 0.0
                
            timestamps = pd.to_datetime(flow_data['timestamp'], errors='coerce')
            valid_timestamps = timestamps.dropna()
            
            if len(valid_timestamps) < 2:
                return 0.0
                
            duration = (valid_timestamps.max() - valid_timestamps.min()).total_seconds()
            return max(duration, 0.0)
            
        except Exception:
            return 0.0
    
    def _calculate_packet_counts(self, flow_data: pd.DataFrame) -> Tuple[int, int]:
        """Calcula conteo de paquetes forward/backward"""
        try:
            if 'direction' in flow_data.columns:
                fwd_count = len(flow_data[flow_data['direction'] == 'fwd'])
                bwd_count = len(flow_data[flow_data['direction'] == 'bwd'])
            else:
                # Estimación 60/40
                total = len(flow_data)
                fwd_count = int(total * 0.6)
                bwd_count = total - fwd_count
                
            return fwd_count, bwd_count
            
        except Exception:
            return len(flow_data) // 2, len(flow_data) // 2
    
    def _calculate_total_bytes(self, flow_data: pd.DataFrame) -> Tuple[float, float]:
        """Calcula bytes totales forward/backward"""
        try:
            if 'packet_size' in flow_data.columns:
                if 'direction' in flow_data.columns:
                    fwd_bytes = flow_data[flow_data['direction'] == 'fwd']['packet_size'].sum()
                    bwd_bytes = flow_data[flow_data['direction'] == 'bwd']['packet_size'].sum()
                else:
                    total_bytes = flow_data['packet_size'].sum()
                    fwd_bytes = total_bytes * 0.6
                    bwd_bytes = total_bytes * 0.4
            else:
                # Valores estimados por defecto
                fwd_bytes = len(flow_data) * 512 * 0.6  # 512 bytes promedio por paquete
                bwd_bytes = len(flow_data) * 512 * 0.4
                
            return float(fwd_bytes), float(bwd_bytes)
            
        except Exception:
            return 0.0, 0.0
    
    def _calculate_packet_length_stats(self, flow_data: pd.DataFrame, direction: str) -> List[float]:
        """Calcula estadísticas de longitud de paquetes por dirección"""
        try:
            if 'packet_size' in flow_data.columns:
                if 'direction' in flow_data.columns:
                    packets = flow_data[flow_data['direction'] == direction]['packet_size']
                else:
                    packets = flow_data['packet_size']  # Usar todos si no hay dirección
                    
                if len(packets) > 0:
                    return [
                        float(packets.max()),
                        float(packets.min()),
                        float(packets.mean()),
                        float(packets.std()) if len(packets) > 1 else 0.0
                    ]
            
            # Valores por defecto
            return [1500.0, 64.0, 512.0, 200.0]  # Max, Min, Mean, Std típicos
            
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]
    
    # Métodos auxiliares para el resto de características
    def _calculate_iat_stats(self, flow_data: pd.DataFrame) -> List[float]:
        """Calcula estadísticas de Inter-Arrival Time"""
        try:
            if 'timestamp' in flow_data.columns and len(flow_data) > 1:
                timestamps = pd.to_datetime(flow_data['timestamp'], errors='coerce').dropna()
                if len(timestamps) > 1:
                    timestamps = timestamps.sort_values()
                    iats = timestamps.diff().dt.total_seconds().dropna()
                    if len(iats) > 0:
                        return [
                            float(iats.mean()),
                            float(iats.std()) if len(iats) > 1 else 0.0,
                            float(iats.max()),
                            float(iats.min())
                        ]
            return [0.1, 0.05, 0.2, 0.01]  # Valores por defecto
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]
    
    def _calculate_direction_iat_stats(self, flow_data: pd.DataFrame, direction: str) -> List[float]:
        """Calcula IAT stats para una dirección específica"""
        # Simplificado - en implementación real sería más complejo
        iat_stats = self._calculate_iat_stats(flow_data)
        total_iat = iat_stats[0] * len(flow_data)
        return [total_iat] + iat_stats  # Total, Mean, Std, Max, Min
    
    def _calculate_tcp_flags(self, flow_data: pd.DataFrame) -> List[float]:
        """Calcula estadísticas de flags TCP"""
        # Implementación simplificada - valores estimados
        return [0.1, 0.1, 0.05, 0.05, 20.0, 20.0, 10.0, 10.0]  # PSH flags, URG flags, Header lengths, Packets/s
    
    def _calculate_general_packet_stats(self, flow_data: pd.DataFrame) -> List[float]:
        """Estadísticas generales de paquetes"""
        try:
            if 'packet_size' in flow_data.columns:
                sizes = flow_data['packet_size']
                return [
                    float(sizes.min()),
                    float(sizes.max()),
                    float(sizes.mean()),
                    float(sizes.std()) if len(sizes) > 1 else 0.0,
                    float(sizes.var()) if len(sizes) > 1 else 0.0
                ]
            return [64.0, 1500.0, 512.0, 200.0, 40000.0]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
    
    def _calculate_flag_counts(self, flow_data: pd.DataFrame) -> List[float]:
        """Conteo de flags TCP"""
        # Valores estimados por defecto
        return [0.0, 1.0, 0.0, 0.1, 5.0, 0.0, 0.0, 0.0]  # FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
    
    def _calculate_bulk_stats(self, flow_data: pd.DataFrame) -> List[float]:
        """Estadísticas de bulk transfer"""
        # Implementación simplificada
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    
    def _calculate_window_stats(self, flow_data: pd.DataFrame) -> List[float]:
        """Estadísticas de window y segmentos"""
        return [8192.0, 8192.0, len(flow_data), 64.0]
    
    def _calculate_active_idle_stats(self, flow_data: pd.DataFrame) -> List[float]:
        """Estadísticas de tiempos activos e idle"""
        return [1.0, 0.5, 2.0, 0.1, 0.1, 0.05, 0.2, 0.01]
    
    def _generate_default_features(self, df: pd.DataFrame) -> List[float]:
        """Genera características por defecto cuando los datos son insuficientes"""
        # Vector de características con valores por defecto representativos
        return [0.0] * len(self.feature_columns)
    
    def _validate_feature_dimensions(self, features_array: np.ndarray) -> np.ndarray:
        """Valida y ajusta las dimensiones del array de características"""
        try:
            expected_features = len(self.feature_columns)
            
            if features_array.shape[1] == expected_features:
                return features_array
            elif features_array.shape[1] < expected_features:
                # Pad con ceros
                pad_width = ((0, 0), (0, expected_features - features_array.shape[1]))
                return np.pad(features_array, pad_width, mode='constant', constant_values=0)
            else:
                # Truncar
                return features_array[:, :expected_features]
                
        except Exception as e:
            logger.error(f"[ERROR] Error validando dimensiones: {e}")
            return features_array
    
    def _update_stats(self, flows_processed: int, start_time: datetime):
        """Actualiza estadísticas de rendimiento"""
        try:
            self.extraction_stats['flows_processed'] += flows_processed
            self.extraction_stats['features_extracted'] += flows_processed * len(self.feature_columns)
            
            extraction_time = (datetime.now() - start_time).total_seconds()
            # Media móvil simple para tiempo promedio
            if self.extraction_stats['avg_extraction_time'] == 0:
                self.extraction_stats['avg_extraction_time'] = extraction_time
            else:
                self.extraction_stats['avg_extraction_time'] = (
                    self.extraction_stats['avg_extraction_time'] * 0.9 + extraction_time * 0.1
                )
        except Exception as e:
            logger.debug(f"[DEBUG] Error actualizando stats: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del extractor"""
        return {
            **self.extraction_stats,
            'feature_count': len(self.feature_columns),
            'config': self.config
        }
    
    def reset_stats(self):
        """Reinicia las estadísticas"""
        self.extraction_stats = {
            'flows_processed': 0,
            'features_extracted': 0,
            'extraction_errors': 0,
            'avg_extraction_time': 0.0
        }


if __name__ == "__main__":
    # Test standalone del extractor
    print("🧪 Testing NetworkFeatureExtractor...")
    
    extractor = NetworkFeatureExtractor()
    
    # Datos de prueba
    test_data = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1', 
            'src_port': 1234,
            'dst_port': 80,
            'packet_size': 512,
            'timestamp': '2024-01-15 10:30:00',
            'direction': 'fwd'
        },
        {
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.100',
            'src_port': 80,
            'dst_port': 1234, 
            'packet_size': 256,
            'timestamp': '2024-01-15 10:30:01',
            'direction': 'bwd'
        }
    ]
    
    features = extractor.extract_features_from_network_data(test_data)
    print(f"✅ Características extraídas: {features.shape}")
    print(f"📊 Stats: {extractor.get_stats()}")
    
    if features.size > 0:
        print(f"🎯 Primeras 10 características: {features[0][:10]}")