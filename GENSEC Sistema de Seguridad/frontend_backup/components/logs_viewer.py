"""
Componente Logs Viewer
======================

Permite a los usuarios ver los logs generados por el sistema, con diferentes
niveles de interpretación para facilitar su comprensión.
"""

import dearpygui.dearpygui as dpg
import logging
import os
import re
from typing import List

class LogsViewerComponent:
    """
    Componente para visualizar y filtrar logs del sistema.
    """
    
    def __init__(self, parent_tag: str, app_controller):
        """
        Args:
            parent_tag: Tag del contenedor padre.
            app_controller: Controlador principal de la UI.
        """
        self.parent_tag = parent_tag
        self.app_controller = app_controller
        self.logger = logging.getLogger("LogsViewer")
        
        self.log_files: List[str] = []
        self.current_log_content: List[str] = []
        self.current_log_file: str = ""
        
        self.ui_tags = {
            "log_selector": "logs_viewer_log_selector",
            "log_content_area": "logs_viewer_log_content_area",
        }

    def render(self):
        """Crear la vista del visualizador de logs."""
        dpg.add_text("📜 System Logs Viewer", color=(100, 255, 100))
        dpg.add_separator()
        
        self._create_controls()
        
        with dpg.child_window(tag="log_content_container", border=True):
            dpg.add_text("Select a log file and an interpretation level.", tag=self.ui_tags['log_content_area'])

        self._find_log_files()

    def _create_controls(self):
        """Crear los controles de selección e interpretación."""
        with dpg.group(horizontal=True):
            dpg.add_text("Log File:")
            dpg.add_combo(
                items=[], 
                tag=self.ui_tags['log_selector'],
                callback=self._on_log_file_selected,
                width=250
            )
            
            dpg.add_spacer(width=50)
            
            dpg.add_text("Interpretation Level:")
            with dpg.group(horizontal=True):
                dpg.add_button(label="Easy", callback=self._render_logs, user_data="easy")
                dpg.add_button(label="Medium", callback=self._render_logs, user_data="medium")
                dpg.add_button(label="Hard", callback=self._render_logs, user_data="hard")

    def _find_log_files(self):
        """Busca archivos .log y .jsonl en el directorio de logs."""
        log_dir = os.path.join(self.app_controller.get_root_dir(), 'logs')
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            self.logger.info(f"Created log directory at: {log_dir}")
            
        self.log_files = [f for f in os.listdir(log_dir) if f.endswith(('.log', '.jsonl'))]
        
        # Si no hay archivos de log, crear algunos simulados
        if not self.log_files:
            self._create_demo_logs(log_dir)
            self.log_files = [f for f in os.listdir(log_dir) if f.endswith(('.log', '.jsonl'))]
        
        if dpg.does_item_exist(self.ui_tags['log_selector']):
            dpg.configure_item(self.ui_tags['log_selector'], items=self.log_files)

    def _on_log_file_selected(self, sender, app_data):
        """Carga el contenido del archivo de log seleccionado."""
        self.current_log_file = app_data
        log_path = os.path.join(self.app_controller.get_root_dir(), 'logs', self.current_log_file)
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Leer las últimas 1000 líneas para no sobrecargar
                self.current_log_content = f.readlines()[-1000:]
            self.logger.info(f"Loaded {len(self.current_log_content)} lines from {self.current_log_file}")
            # Por defecto, mostrar en modo "Hard" al cargar
            self._render_logs(user_data="hard")
        except Exception as e:
            self.logger.error(f"Failed to read log file {log_path}: {e}")
            self.current_log_content = [f"Error reading log file: {e}"]
            self._render_logs(user_data="hard")

    def _render_logs(self, sender=None, app_data=None, user_data: str = "hard"):
        """Procesa y muestra los logs según el nivel de interpretación."""
        if not self.current_log_content:
            return

        # Limpiar el área de contenido
        if dpg.does_item_exist("log_content_container"):
            children = dpg.get_item_children("log_content_container", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Agregar contenido al contenedor
            if user_data == "hard":
                # Nivel Difícil: Mostrar el log en bruto
                for line in self.current_log_content:
                    dpg.add_text(line.strip(), wrap=0, parent="log_content_container") # wrap=0 para scroll horizontal
            
            elif user_data == "medium":
                # Nivel Medio: Formatear en una tabla
                with dpg.table(header_row=True, resizable=True, policy=dpg.mvTable_SizingStretchProp, parent="log_content_container"):
                    dpg.add_table_column(label="Timestamp")
                    dpg.add_table_column(label="Level")
                    dpg.add_table_column(label="Message")
                    
                    for line in self.current_log_content:
                        match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s*-\s*.*?\s*-\s*(\w+)\s*-\s*(.*)', line)
                        if match:
                            with dpg.table_row():
                                dpg.add_text(match.group(1))
                                dpg.add_text(match.group(2))
                                dpg.add_text(match.group(3))

            elif user_data == "easy":
                # Nivel Fácil: Mostrar solo resultados importantes
                for line in self.current_log_content:
                    line_lower = line.lower()
                    # Buscar palabras clave que indiquen un resultado importante
                    if "threat detected" in line_lower or "error" in line_lower or "failed" in line_lower or "shutdown" in line_lower or "iniciando" in line_lower:
                        simplified_line = self._simplify_log_line(line)
                        color = (255, 255, 255)
                        if "error" in line_lower or "failed" in line_lower:
                            color = (255, 100, 100)
                        elif "threat" in line_lower:
                            color = (255, 165, 0)
                        elif "iniciando" in line_lower or "shutdown" in line_lower:
                            color = (100, 200, 255)
                        
                        dpg.add_text(simplified_line, color=color, parent="log_content_container")

    def _simplify_log_line(self, line: str) -> str:
        """Traduce una línea de log a un formato más simple."""
        line_lower = line.lower()
        
        if "threat detected" in line_lower:
            return "🚨 ¡Amenaza Detectada! El sistema encontró una posible amenaza."
        if "error" in line_lower:
            return "❌ Error: Ocurrió un error en el sistema. Revisa los detalles en modo Medio/Difícil."
        if "failed" in line_lower:
            return "⚠️ Fallo: Una operación no pudo completarse."
        if "iniciando" in line_lower:
            return "🚀 Sistema Iniciado: El antivirus ha comenzado a funcionar."
        if "shutdown" in line_lower:
            return "🛑 Sistema Detenido: El antivirus se ha cerrado de forma segura."
        
        # Extraer el mensaje principal si no hay una simplificación directa
        match = re.search(r'-\s*(.*)', line.split(' - ')[-1])
        return f"ℹ️ Info: {match.group(1).strip()}" if match else line.strip()
    
    def _create_demo_logs(self, log_dir):
        """Crear archivos de log de demostración"""
        import datetime
        now = datetime.datetime.now()
        
        # Crear antivirus.log
        antivirus_log = os.path.join(log_dir, "antivirus.log")
        with open(antivirus_log, 'w') as f:
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - AntivirusEngine - INFO - 🚀 Sistema antivirus iniciado\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - KeyloggerDetector - WARNING - Proceso sospechoso detectado: Code.exe\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - BehaviorAnalyzer - ERROR - Actividad maliciosa bloqueada\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - QuarantineManager - INFO - Archivo movido a cuarentena: malware.exe\n")
        
        # Crear threats.log
        threats_log = os.path.join(log_dir, "threats.log")
        with open(threats_log, 'w') as f:
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - ThreatDetector - HIGH - Keylogger detectado en C:\\Windows\\System32\\malware.exe\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - ThreatDetector - MEDIUM - Comportamiento sospechoso en python.exe\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - ThreatDetector - LOW - Archivo temporal creado: temp.tmp\n")
        
        # Crear system.log
        system_log = os.path.join(log_dir, "system.log")
        with open(system_log, 'w') as f:
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - SystemMonitor - INFO - CPU Usage: 45%\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - SystemMonitor - INFO - Memory Usage: 62%\n")
            f.write(f"{now.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - SystemMonitor - WARNING - High resource usage detected\n")
        
        self.logger.info("Created demo log files")
