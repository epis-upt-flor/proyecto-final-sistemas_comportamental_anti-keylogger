"""
Componente Dashboard Principal
============================

Dashboard principal con métricas en tiempo real, gráficos de rendimiento
y resumen del estado del sistema antivirus.
"""

import dearpygui.dearpygui as dpg
import time
import threading
from typing import Dict, List, Any, Optional
from collections import deque
import logging


class DashboardComponent:
    """
    Componente del dashboard principal
    
    Muestra:
    - Métricas clave del sistema
    - Gráficos de rendimiento en tiempo real
    - Estado de protección
    - Resumen de amenazas
    - Estadísticas de red y procesos
    """
    
    def __init__(self, parent_tag: str):
        """
        Args:
            parent_tag: Tag del contenedor padre donde crear el dashboard
        """
        self.parent_tag = parent_tag
        self.logger = logging.getLogger("Dashboard")
        
        # Datos para gráficos
        self.plot_data = {
            'cpu_history': deque(maxlen=60),     # 1 minuto de historia
            'memory_history': deque(maxlen=60),
            'threats_history': deque(maxlen=60),
            'network_history': deque(maxlen=60),
            'time_stamps': deque(maxlen=60)
        }
        
        # Estado actual
        self.current_metrics = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'threats_detected': 0,
            'processes_monitored': 0,
            'protection_status': 'Active',
            'last_scan': 'Never',
            'uptime': 0
        }
        
        # Tags de elementos UI
        self.ui_tags = {
            'cpu_plot': 'dashboard_cpu_plot',
            'memory_plot': 'dashboard_memory_plot',
            'threats_plot': 'dashboard_threats_plot',
            'network_plot': 'dashboard_network_plot',
            'protection_status': 'dashboard_protection_status',
            'threats_count': 'dashboard_threats_count',
            'cpu_metric': 'dashboard_cpu_metric',
            'memory_metric': 'dashboard_memory_metric',
            'processes_metric': 'dashboard_processes_metric',
            'uptime_metric': 'dashboard_uptime_metric'
        }
        
        self.is_updating = False
        self.update_thread = None
        
    def create(self):
        """Crear el dashboard completo responsivo"""
        try:
            # Usar dimensiones por defecto que se ajustarán automáticamente
            viewport_width = 1200  # Ancho por defecto
            viewport_height = 800  # Alto por defecto
            
            # Intentar obtener dimensiones reales si están disponibles
            try:
                actual_width = dpg.get_viewport_width()
                actual_height = dpg.get_viewport_height()
                if actual_width > 0 and actual_height > 0:
                    viewport_width = actual_width - 250  # Restar ancho del sidebar
                    viewport_height = actual_height - 100  # Restar espacio para header
            except:
                pass  # Usar valores por defecto si no están disponibles
            
            self._create_header()
            self._create_metrics_row(viewport_width)
            dpg.add_spacer(height=15)
            self._create_charts_section(viewport_width, viewport_height)
            dpg.add_spacer(height=15)
            self._create_suspicious_processes_list(viewport_width)
                
            self.logger.info("Dashboard created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating dashboard: {e}")
            
    def _create_header(self):
        """Crear header del dashboard"""
        with dpg.group(horizontal=True):
            dpg.add_text("📊 System Dashboard", color=(0, 150, 255))
            dpg.add_spacer(width=50)
            with dpg.group():
                dpg.add_text("Last Updated: ", color=(150, 150, 150))
                dpg.add_text("Never", tag="dashboard_last_update", color=(200, 200, 200))
            
        dpg.add_separator()
            
    def _create_metrics_row(self, viewport_width):
        """Crear fila de métricas principales responsiva"""
        # Calcular ancho de cada métrica basado en viewport
        metric_width = (viewport_width - 100) // 5  # 5 métricas con espaciado
        
        with dpg.group(horizontal=True):
            # Métricas en cards responsivas
            self._create_metric_card(
                "🛡️ Protection Status",
                "Active",
                (0, 255, 100),
                self.ui_tags['protection_status'],
                metric_width
            )
            
            dpg.add_spacer(width=15)
            
            self._create_metric_card(
                "🦠 Threats Detected",
                "0",
                (255, 100, 100),
                self.ui_tags['threats_count'],
                metric_width
            )
            
            dpg.add_spacer(width=15)
            
            self._create_metric_card(
                "💻 CPU Usage",
                "0%",
                (100, 150, 255),
                self.ui_tags['cpu_metric'],
                metric_width
            )
            
            dpg.add_spacer(width=15)
            
            self._create_metric_card(
                "🧠 Memory Usage",
                "0%",
                (255, 150, 100),
                self.ui_tags['memory_metric'],
                metric_width
            )
            
            dpg.add_spacer(width=15)
            
            self._create_metric_card(
                "📊 Processes",
                "0",
                (150, 255, 150),
                self.ui_tags['processes_metric'],
                metric_width
            )
            
            dpg.add_spacer(width=20)
            
            self._create_metric_card(
                "⏱️ Uptime",
                "0s",
                (100, 255, 200),
                self.ui_tags['uptime_metric']
            )
            
    def _create_metric_card(self, title: str, value: str, color: tuple, value_tag: str, width: int = 180):
        """Crear una tarjeta de métrica responsiva"""
        with dpg.child_window(width=width, height=100, border=True):
            dpg.add_spacer(height=5)
            dpg.add_text(title, color=color)
            dpg.add_spacer(height=10)
            
            # Valor grande y centrado
            dpg.add_spacer(width=10)
            dpg.add_text(value, tag=value_tag, color=(255, 255, 255))
                
    def _create_charts_section(self, viewport_width, viewport_height):
        """Crear sección de gráficos de rendimiento responsiva"""
        dpg.add_text("📈 Real-time Performance", color=(0, 200, 100))
        dpg.add_separator()
        
        # Calcular dimensiones responsivas
        chart_width = (viewport_width - 60) // 2  # 2 gráficos por fila con espaciado
        chart_height = (viewport_height - 300) // 2  # 2 filas de gráficos
        plot_width = chart_width - 40  # Restar padding interno
        plot_height = chart_height - 80  # Restar espacio para título
        
        # Fila superior de gráficos
        with dpg.group(horizontal=True):
            # Gráfico de CPU
            with dpg.child_window(width=chart_width, height=chart_height, border=True):
                dpg.add_text("💻 CPU Usage (%)", color=(100, 150, 255))
                
                with dpg.plot(width=plot_width, height=plot_height, tag=self.ui_tags['cpu_plot']):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time")
                    dpg.add_plot_axis(dpg.mvYAxis, label="CPU %", tag="cpu_y_axis")
                    
                    # Línea de CPU
                    dpg.add_line_series(
                        [], [], 
                        label="CPU Usage",
                        parent="cpu_y_axis",
                        tag="cpu_line_series"
                    )
            
            dpg.add_spacer(width=20)
            
            # Gráfico de Memoria
            with dpg.child_window(width=chart_width, height=chart_height, border=True):
                dpg.add_text("🧠 Memory Usage (%)", color=(255, 150, 100))
                
                with dpg.plot(width=plot_width, height=plot_height, tag=self.ui_tags['memory_plot']):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time")
                    dpg.add_plot_axis(dpg.mvYAxis, label="Memory %", tag="memory_y_axis")
                    
                    # Línea de Memoria
                    dpg.add_line_series(
                        [], [], 
                        label="Memory Usage",
                        parent="memory_y_axis",
                        tag="memory_line_series"
                    )
        
        dpg.add_spacer(height=15)
        
        # Fila inferior de gráficos
        with dpg.group(horizontal=True):
            # Gráfico de Amenazas
            with dpg.child_window(width=chart_width, height=chart_height, border=True):
                dpg.add_text("🦠 Threats Detected", color=(255, 100, 100))
                
                with dpg.plot(width=plot_width, height=plot_height, tag=self.ui_tags['threats_plot']):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time")
                    dpg.add_plot_axis(dpg.mvYAxis, label="Threats", tag="threats_y_axis")
                    
                    # Línea de Amenazas
                    dpg.add_line_series(
                        [], [], 
                        label="Threats",
                        parent="threats_y_axis",
                        tag="threats_line_series"
                    )
            
            dpg.add_spacer(width=20)
            
            # Gráfico de Red
            with dpg.child_window(width=chart_width, height=chart_height, border=True):
                dpg.add_text("🌐 Network Activity", color=(200, 100, 255))
                
                with dpg.plot(width=plot_width, height=plot_height, tag=self.ui_tags['network_plot']):
                    dpg.add_plot_legend()
                    dpg.add_plot_axis(dpg.mvXAxis, label="Time")
                    dpg.add_plot_axis(dpg.mvYAxis, label="Connections", tag="network_y_axis")
                    
                    # Línea de Red
                    dpg.add_line_series(
                        [], [], 
                        label="Network",
                        parent="network_y_axis",
                        tag="network_line_series"
                    )
                    
    def _create_suspicious_processes_list(self, viewport_width):
        """Crear tabla responsiva para procesos sospechosos"""
        dpg.add_text("🚨 Suspicious Processes", color=(255, 100, 100))
        dpg.add_separator()
        
        # Calcular altura disponible para la tabla
        table_height = 180  # Altura fija pero ajustable
        
        with dpg.child_window(width=viewport_width, height=table_height, border=True, tag="suspicious_processes_window"):
            with dpg.table(header_row=True, resizable=True, policy=dpg.mvTable_SizingStretchProp,
                           borders_outerH=True, borders_innerV=True, borders_innerH=True, borders_outerV=True,
                           tag="suspicious_processes_table"):
                dpg.add_table_column(label="Timestamp")
                dpg.add_table_column(label="Process/File")
                dpg.add_table_column(label="Type")
                dpg.add_table_column(label="Risk")
                dpg.add_table_column(label="Actions")

    def start_updates(self, app_controller):
        """Iniciar actualizaciones automáticas del dashboard"""
        if self.is_updating:
            return
        
        self.app_controller = app_controller
        self.is_updating = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        self.logger.info("Dashboard updates started")

    def stop_updates(self):
        """Detener actualizaciones automáticas"""
        self.is_updating = False
        if self.update_thread:
            self.update_thread.join(timeout=1.0)
        self.logger.info("Dashboard updates stopped")
        
    def _update_loop(self):
        """Loop de actualización del dashboard"""
        while self.is_updating:
            try:
                self._update_metrics()
                self._update_plots()
                self._update_suspicious_processes_list()
                time.sleep(1.0)  # Actualizar cada segundo

            except Exception as e:
                self.logger.error(f"Error in dashboard update loop: {e}")

    def _update_metrics(self):
        """Actualizar métricas del dashboard"""
        try:
            # Obtener datos del controlador principal
            if not hasattr(self, 'app_controller'):
                return

            stats = self.app_controller.system_stats

            # Datos reales del sistema
            cpu_usage = stats.get('cpu_usage', 0.0)
            memory_usage = stats.get('memory_usage', 0.0)
            process_count = stats.get('processes_monitored', 0)
            threats_detected = stats.get('threats_detected', 0)
            uptime = int(stats.get('uptime', 0))

            # Actualizar métricas
            self.current_metrics.update({
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'processes_monitored': process_count,
                'threats_detected': threats_detected,
                'uptime': uptime
            })

            # Actualizar UI
            if dpg.does_item_exist(self.ui_tags['cpu_metric']):
                dpg.set_value(self.ui_tags['cpu_metric'], f"{cpu_usage:.1f}%")
                dpg.set_value(self.ui_tags['memory_metric'], f"{memory_usage:.1f}%")
                dpg.set_value(self.ui_tags['processes_metric'], str(process_count))
                dpg.set_value(self.ui_tags['uptime_metric'], self._format_uptime(uptime))
                dpg.set_value(self.ui_tags['threats_count'], str(threats_detected))
                dpg.set_value("dashboard_last_update", time.strftime("%H:%M:%S"))

        except Exception as e:
            self.logger.error(f"Error updating metrics: {e}")

    def _update_plots(self):
        """Actualizar gráficos en tiempo real"""
        try:
            current_time = time.time()
            
            # Agregar datos a las colas
            self.plot_data['time_stamps'].append(current_time)
            self.plot_data['cpu_history'].append(self.current_metrics['cpu_usage'])
            self.plot_data['memory_history'].append(self.current_metrics['memory_usage'])
            self.plot_data['threats_history'].append(self.current_metrics['threats_detected'])
            
            # Simular actividad de red
            network_activity = self.current_metrics.get('network_activity', 0) # Usar métrica si existe
            self.plot_data['network_history'].append(network_activity)

            # Convertir a listas para Dear PyGui
            time_values = list(range(len(self.plot_data['time_stamps'])))
            
            # Actualizar gráficos
            if dpg.does_item_exist("cpu_line_series"):
                dpg.set_value("cpu_line_series", [time_values, list(self.plot_data['cpu_history'])])
                
            if dpg.does_item_exist("memory_line_series"):
                dpg.set_value("memory_line_series", [time_values, list(self.plot_data['memory_history'])])
                
            if dpg.does_item_exist("threats_line_series"):
                dpg.set_value("threats_line_series", [time_values, list(self.plot_data['threats_history'])])
                
            if dpg.does_item_exist("network_line_series"):
                dpg.set_value("network_line_series", [time_values, list(self.plot_data['network_history'])])

        except Exception as e:
            self.logger.error(f"Error updating plots: {e}")

    def _update_suspicious_processes_list(self):
        """Actualizar la lista de procesos sospechosos (versión simplificada)"""
        # Saltarse actualizaciones que causan problemas con la tabla
        # La funcionalidad completa está disponible en Real-time Monitor
        pass


    def _format_uptime(self, seconds: int) -> str:
        """Formatear tiempo de actividad"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds//60}m {seconds%60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
            
    def update_threat_count(self, count: int):
        """Actualizar contador de amenazas"""
        self.current_metrics['threats_detected'] = count
        
    def update_protection_status(self, status: str):
        """Actualizar estado de protección"""
        self.current_metrics['protection_status'] = status
        if dpg.does_item_exist(self.ui_tags['protection_status']):
            dpg.set_value(self.ui_tags['protection_status'], status)
