"""
Monitor de Rendimiento para la UI
=================================

Monitorea el rendimiento de la aplicación Dear PyGui y del sistema.
Ayuda a optimizar la experiencia del usuario y detectar problemas.
"""

import time
import threading
import psutil
from typing import Dict, List, Any
from collections import deque
import logging


class PerformanceMonitor:
    """
    Monitor de rendimiento del sistema y aplicación
    
    Rastrea:
    - FPS de la UI
    - Uso de CPU/memoria
    - Tiempo de respuesta
    - Estadísticas del antivirus
    """
    
    def __init__(self, history_size: int = 300):  # 5 minutos a 1 sample/segundo
        """
        Args:
            history_size: Número de muestras a mantener en historial
        """
        self.history_size = history_size
        self.logger = logging.getLogger("PerformanceMonitor")
        
        # Datos de rendimiento
        self.metrics = {
            'fps': deque(maxlen=history_size),
            'cpu_percent': deque(maxlen=history_size),
            'memory_percent': deque(maxlen=history_size),
            'memory_mb': deque(maxlen=history_size),
            'gpu_usage': deque(maxlen=history_size),
            'response_time_ms': deque(maxlen=history_size),
            'threats_per_minute': deque(maxlen=history_size),
            'scans_per_minute': deque(maxlen=history_size)
        }
        
        # Control de monitoreo
        self.is_monitoring = False
        self.monitor_thread = None
        self.last_frame_time = time.time()
        self.frame_count = 0
        
        # Estadísticas calculadas
        self.current_stats = {
            'avg_fps': 0.0,
            'avg_cpu': 0.0,
            'avg_memory': 0.0,
            'max_response_time': 0.0,
            'total_threats': 0,
            'performance_score': 100.0
        }
        
        # Umbrales de rendimiento
        self.thresholds = {
            'min_fps': 30.0,
            'max_cpu': 80.0,
            'max_memory': 85.0,
            'max_response_time': 100.0  # ms
        }
        
    def start_monitoring(self):
        """Iniciar monitoreo de rendimiento"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("Performance monitoring started")
        
    def stop_monitoring(self):
        """Detener monitoreo"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        self.logger.info("Performance monitoring stopped")
        
    def _monitoring_loop(self):
        """Loop principal de monitoreo"""
        last_sample_time = time.time()
        
        while self.is_monitoring:
            try:
                current_time = time.time()
                
                # Tomar muestra cada segundo
                if current_time - last_sample_time >= 1.0:
                    self._take_sample()
                    self._calculate_stats()
                    last_sample_time = current_time
                
                time.sleep(0.1)  # Check cada 100ms
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                
    def _take_sample(self):
        """Tomar muestra de rendimiento actual"""
        try:
            # CPU y memoria del sistema
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            # Proceso actual
            process = psutil.Process()
            process_memory_mb = process.memory_info().rss / 1024 / 1024
            
            # Almacenar métricas
            self.metrics['cpu_percent'].append(cpu_percent)
            self.metrics['memory_percent'].append(memory.percent)
            self.metrics['memory_mb'].append(process_memory_mb)
            
            # FPS (basado en frame_rate si está disponible)
            current_fps = self._calculate_fps()
            self.metrics['fps'].append(current_fps)
            
            # GPU usage (estimado, Dear PyGui no expone métricas directas)
            gpu_usage = self._estimate_gpu_usage()
            self.metrics['gpu_usage'].append(gpu_usage)
            
            # Response time (placeholder - se actualiza desde UI)
            if not self.metrics['response_time_ms']:
                self.metrics['response_time_ms'].append(0.0)
                
        except Exception as e:
            self.logger.error(f"Error taking performance sample: {e}")
            
    def _calculate_fps(self) -> float:
        """Calcular FPS estimado"""
        current_time = time.time()
        delta_time = current_time - self.last_frame_time
        
        if delta_time > 0:
            fps = 1.0 / delta_time
        else:
            fps = 60.0  # Default
            
        self.last_frame_time = current_time
        return min(fps, 120.0)  # Cap a 120 FPS
        
    def _estimate_gpu_usage(self) -> float:
        """Estimar uso de GPU (aproximado)"""
        try:
            # En sistemas con GPU integrada, correlacionar con CPU
            cpu_percent = self.metrics['cpu_percent'][-1] if self.metrics['cpu_percent'] else 0
            
            # Estimación simple: GPU usage correlacionado con CPU para Dear PyGui
            estimated_gpu = min(cpu_percent * 0.8, 100.0)
            return estimated_gpu
            
        except:
            return 0.0
            
    def _calculate_stats(self):
        """Calcular estadísticas resumidas"""
        try:
            # FPS promedio
            if self.metrics['fps']:
                self.current_stats['avg_fps'] = sum(self.metrics['fps']) / len(self.metrics['fps'])
            
            # CPU promedio
            if self.metrics['cpu_percent']:
                self.current_stats['avg_cpu'] = sum(self.metrics['cpu_percent']) / len(self.metrics['cpu_percent'])
            
            # Memoria promedio
            if self.metrics['memory_percent']:
                self.current_stats['avg_memory'] = sum(self.metrics['memory_percent']) / len(self.metrics['memory_percent'])
            
            # Tiempo de respuesta máximo
            if self.metrics['response_time_ms']:
                self.current_stats['max_response_time'] = max(self.metrics['response_time_ms'])
            
            # Calcular score de rendimiento general
            self.current_stats['performance_score'] = self._calculate_performance_score()
            
        except Exception as e:
            self.logger.error(f"Error calculating stats: {e}")
            
    def _calculate_performance_score(self) -> float:
        """Calcular score de rendimiento (0-100)"""
        score = 100.0
        
        # Penalizar FPS bajo
        if self.current_stats['avg_fps'] < self.thresholds['min_fps']:
            fps_penalty = (self.thresholds['min_fps'] - self.current_stats['avg_fps']) * 2
            score -= min(fps_penalty, 30.0)
        
        # Penalizar CPU alto
        if self.current_stats['avg_cpu'] > self.thresholds['max_cpu']:
            cpu_penalty = (self.current_stats['avg_cpu'] - self.thresholds['max_cpu']) * 0.5
            score -= min(cpu_penalty, 20.0)
        
        # Penalizar memoria alta
        if self.current_stats['avg_memory'] > self.thresholds['max_memory']:
            memory_penalty = (self.current_stats['avg_memory'] - self.thresholds['max_memory']) * 0.8
            score -= min(memory_penalty, 25.0)
        
        # Penalizar tiempo de respuesta alto
        if self.current_stats['max_response_time'] > self.thresholds['max_response_time']:
            response_penalty = (self.current_stats['max_response_time'] - self.thresholds['max_response_time']) * 0.1
            score -= min(response_penalty, 15.0)
        
        return max(score, 0.0)
        
    def record_response_time(self, response_time_ms: float):
        """Registrar tiempo de respuesta de UI"""
        self.metrics['response_time_ms'].append(response_time_ms)
        
    def record_threat_detection(self):
        """Registrar detección de amenaza"""
        # Incrementar contador por minuto
        current_minute = int(time.time() // 60)
        # Implementación simplificada
        pass
        
    def get_current_metrics(self) -> Dict[str, Any]:
        """Obtener métricas actuales"""
        return {
            'fps': self.metrics['fps'][-1] if self.metrics['fps'] else 0.0,
            'cpu_percent': self.metrics['cpu_percent'][-1] if self.metrics['cpu_percent'] else 0.0,
            'memory_percent': self.metrics['memory_percent'][-1] if self.metrics['memory_percent'] else 0.0,
            'memory_mb': self.metrics['memory_mb'][-1] if self.metrics['memory_mb'] else 0.0,
            'gpu_usage': self.metrics['gpu_usage'][-1] if self.metrics['gpu_usage'] else 0.0,
            'performance_score': self.current_stats['performance_score']
        }
        
    def get_historical_data(self, metric: str, samples: int = None) -> List[float]:
        """
        Obtener datos históricos de una métrica
        
        Args:
            metric: Nombre de la métrica
            samples: Número de muestras (None para todas)
            
        Returns:
            Lista de valores históricos
        """
        if metric not in self.metrics:
            return []
            
        data = list(self.metrics[metric])
        if samples:
            return data[-samples:]
        return data
        
    def get_performance_summary(self) -> Dict[str, Any]:
        """Obtener resumen de rendimiento"""
        return {
            'current_metrics': self.get_current_metrics(),
            'averages': {
                'fps': self.current_stats['avg_fps'],
                'cpu': self.current_stats['avg_cpu'],
                'memory': self.current_stats['avg_memory']
            },
            'performance_score': self.current_stats['performance_score'],
            'status': self._get_performance_status(),
            'recommendations': self._get_recommendations()
        }
        
    def _get_performance_status(self) -> str:
        """Obtener estado de rendimiento"""
        score = self.current_stats['performance_score']
        
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Good"
        elif score >= 60:
            return "Fair"
        elif score >= 40:
            return "Poor"
        else:
            return "Critical"
            
    def _get_recommendations(self) -> List[str]:
        """Obtener recomendaciones de optimización"""
        recommendations = []
        
        if self.current_stats['avg_fps'] < self.thresholds['min_fps']:
            recommendations.append("Consider reducing UI update frequency for better FPS")
            
        if self.current_stats['avg_cpu'] > self.thresholds['max_cpu']:
            recommendations.append("High CPU usage detected - check background processes")
            
        if self.current_stats['avg_memory'] > self.thresholds['max_memory']:
            recommendations.append("High memory usage - consider closing other applications")
            
        if self.current_stats['max_response_time'] > self.thresholds['max_response_time']:
            recommendations.append("UI response time is slow - optimize expensive operations")
            
        if not recommendations:
            recommendations.append("Performance is optimal")
            
        return recommendations
        
    def reset_metrics(self):
        """Resetear todas las métricas"""
        for metric in self.metrics:
            self.metrics[metric].clear()
            
        self.current_stats = {
            'avg_fps': 0.0,
            'avg_cpu': 0.0, 
            'avg_memory': 0.0,
            'max_response_time': 0.0,
            'total_threats': 0,
            'performance_score': 100.0
        }
        
        self.logger.info("Performance metrics reset")