import dearpygui.dearpygui as dpg
import time
import threading
from typing import Dict, List, Any, Optional
from collections import deque
import logging
import os
import subprocess

class RealtimeMonitorComponent:
    """
    Componente para monitorizar y gestionar amenazas en tiempo real.
    """
    
    def __init__(self, parent_tag: str, app_controller):
        """
        Args:
            parent_tag: Tag del contenedor padre.
            app_controller: Controlador principal de la UI para acceder a datos y acciones.
        """
        self.parent_tag = parent_tag
        self.app_controller = app_controller
        self.logger = logging.getLogger("RealtimeMonitor")
        
        self.is_updating = False
        self.update_thread = None
        self.update_interval = 1.0  # Segundos
        
        self.ui_tags = {
            "detections_table": "realtime_monitor_detections_table",
            "update_status": "realtime_monitor_update_status",
            "auto_quarantine_checkbox": "realtime_monitor_auto_quarantine_checkbox"
        }

    def render(self):
        """Crear la vista del monitor en tiempo real."""
        self._create_header()
        self._create_detections_table()
        self.start_updates()

    def _create_header(self):
        """Crear el header con controles."""
        with dpg.group(horizontal=True):
            dpg.add_text("🔴 Real-time System Monitor", color=(255, 80, 80))
            dpg.add_spacer(width=50)
            dpg.add_checkbox(label="Auto-quarantine", tag=self.ui_tags['auto_quarantine_checkbox'], callback=self._toggle_auto_quarantine)
        
        with dpg.group(horizontal=True):
            dpg.add_text("Update Frequency:")
            dpg.add_combo(["Real-time (0.5s)", "1s", "2s", "5s", "10s"], default_value="1s", width=150, callback=self._set_update_interval)
            dpg.add_spacer(width=20)
            dpg.add_text("Status: ", tag=self.ui_tags['update_status'], color=(0, 255, 0))

        dpg.add_separator()

    def _create_detections_table(self):
        """Crear la tabla para mostrar las detecciones."""
        with dpg.child_window(tag="detections_table_container", border=False):
            with dpg.table(header_row=True, resizable=True, policy=dpg.mvTable_SizingStretchProp,
                           borders_outerH=True, borders_innerV=True, borders_innerH=True, borders_outerV=True,
                           tag=self.ui_tags['detections_table']):
                dpg.add_table_column(label="Timestamp", width_fixed=True, init_width_or_weight=100)
                dpg.add_table_column(label="Type", width_fixed=True, init_width_or_weight=100)
                dpg.add_table_column(label="Process/File", width_stretch=True, init_width_or_weight=250)
                dpg.add_table_column(label="Risk", width_fixed=True, init_width_or_weight=80)
                dpg.add_table_column(label="Actions", width_fixed=True, init_width_or_weight=420)

    def start_updates(self):
        """Iniciar el hilo de actualización de la tabla."""
        if not self.is_updating:
            self.is_updating = True
            self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
            self.update_thread.start()
            self.logger.info("Real-time monitor updates started.")

    def stop_updates(self):
        """Detener el hilo de actualización."""
        self.is_updating = False
        if self.update_thread:
            self.update_thread.join(timeout=1)
        self.logger.info("Real-time monitor updates stopped.")

    def _update_loop(self):
        """Bucle que actualiza la tabla de detecciones periódicamente."""
        while self.is_updating:
            try:
                dpg.set_value(self.ui_tags['update_status'], "Updating...")
                dpg.configure_item(self.ui_tags['update_status'], color=(255, 255, 0))
                
                self._update_detections_list()
                
                dpg.set_value(self.ui_tags['update_status'], "Active")
                dpg.configure_item(self.ui_tags['update_status'], color=(0, 255, 0))
                
                time.sleep(self.update_interval)
            except Exception as e:
                self.logger.error(f"Error in update loop: {e}", exc_info=True)
                dpg.set_value(self.ui_tags['update_status'], "Error")
                dpg.configure_item(self.ui_tags['update_status'], color=(255, 0, 0))
                time.sleep(5) # Esperar antes de reintentar en caso de error

    def _update_detections_list(self):
        """Obtiene las amenazas del controlador y actualiza la tabla."""
        if not dpg.does_item_exist(self.ui_tags['detections_table']):
            return

        threats = self.app_controller.get_active_threats()
        
        # Limpiar tabla manteniendo la estructura
        if dpg.does_item_exist(self.ui_tags['detections_table']):
            # Solo limpiar las filas, no las columnas
            children = dpg.get_item_children(self.ui_tags['detections_table'], 1)  # slot 1 = table rows
            if children:
                for child in children:
                    dpg.delete_item(child)

        for threat in threats:
            with dpg.table_row(parent=self.ui_tags['detections_table']):
                dpg.add_text(threat.get('timestamp', 'N/A'))
                dpg.add_text(threat.get('type', 'N/A'))
                dpg.add_text(threat.get('path', threat.get('name', 'N/A')))
                
                risk = threat.get('risk', 'LOW')
                color = (0, 255, 0)
                if risk == 'HIGH': color = (255, 0, 0)
                elif risk == 'MEDIUM': color = (255, 165, 0)
                dpg.add_text(risk, color=color)

                with dpg.group(horizontal=True):
                    dpg.add_button(label="Details", small=True, user_data=threat, callback=self._show_details)
                    dpg.add_button(label="Locate", small=True, user_data=threat, callback=self._locate_file)
                    dpg.add_button(label="Stop", small=True, user_data=threat, callback=self._stop_process)
                    dpg.add_button(label="Quarantine", small=True, user_data=threat, callback=self._quarantine_file)
                    dpg.add_button(label="Whitelist", small=True, user_data=threat, callback=self._whitelist_item)

    # --- Callbacks de la Interfaz ---

    def _set_update_interval(self, sender, app_data):
        """Establece el intervalo de actualización."""
        try:
            value = app_data.split('(')[-1].replace('s)', '')
            self.update_interval = float(value)
            self.logger.info(f"Update interval set to {self.update_interval}s")
        except ValueError:
            self.update_interval = 1.0 # Fallback
            self.logger.warning(f"Invalid update interval, falling back to {self.update_interval}s")

    def _toggle_auto_quarantine(self, sender, app_data):
        """Activa/desactiva la cuarentena automática."""
        enabled = dpg.get_value(sender)
        self.app_controller.set_setting('auto_quarantine', enabled)
        self.logger.info(f"Auto-quarantine {'enabled' if enabled else 'disabled'}")

    def _show_details(self, sender, app_data, user_data):
        """Muestra una ventana modal con detalles de la amenaza."""
        # Cerrar cualquier modal existente primero
        if dpg.does_item_exist("threat_details_modal"):
            dpg.delete_item("threat_details_modal")
            
        with dpg.window(
            label="Threat Details", 
            modal=True, 
            show=True, 
            tag="threat_details_modal", 
            width=400, 
            height=300,
            on_close=self._close_threat_details_modal
        ):
            dpg.add_text(f"Process/File: {user_data.get('name', 'N/A')}")
            dpg.add_text(f"Path: {user_data.get('path', 'N/A')}")
            dpg.add_text(f"PID: {user_data.get('pid', 'N/A')}")
            dpg.add_text(f"Risk: {user_data.get('risk', 'N/A')}")
            dpg.add_text(f"Type: {user_data.get('type', 'N/A')}")
            dpg.add_separator()
            dpg.add_text("Details:", color=(255, 255, 0))
            dpg.add_text(str(user_data.get('details', 'No additional details available.')), wrap=380)
            dpg.add_separator()
            dpg.add_button(label="Close", width=-1, callback=self._close_threat_details_modal)

    def _locate_file(self, sender, app_data, user_data):
        """Abre el explorador de archivos en la ubicación del archivo."""
        path = user_data.get('path')
        if path and os.path.exists(path):
            try:
                # 'subprocess.run' es más seguro que 'os.system'
                subprocess.run(['explorer', '/select,', os.path.normpath(path)])
                self.logger.info(f"Located file: {path}")
            except Exception as e:
                self.logger.error(f"Failed to locate file {path}: {e}")
        else:
            self.logger.warning(f"Cannot locate. Path not found or does not exist: {path}")

    def _stop_process(self, sender, app_data, user_data):
        """Solicita al backend que detenga un proceso por su PID."""
        pid = user_data.get('pid')
        if pid:
            self.logger.info(f"Requesting to stop process with PID: {pid}")
            # Esta función debe existir en el app_controller y comunicarse con el backend
            success, message = self.app_controller.perform_backend_action('stop_process', {'pid': pid})
            if success:
                self.logger.info(f"Backend confirmed process {pid} stopped.")
            else:
                self.logger.error(f"Backend failed to stop process {pid}: {message}")
        else:
            self.logger.warning("Cannot stop process. PID not available.")

    def _quarantine_file(self, sender, app_data, user_data):
        """Solicita al backend que ponga en cuarentena un archivo."""
        path = user_data.get('path')
        if path:
            self.logger.info(f"Requesting to quarantine file: {path}")
            # Esta función debe existir en el app_controller
            success, message = self.app_controller.perform_backend_action('quarantine_file', {'path': path})
            if success:
                self.logger.info(f"Backend confirmed file quarantined: {path}")
            else:
                self.logger.error(f"Backend failed to quarantine file {path}: {message}")
        else:
            self.logger.warning("Cannot quarantine. Path not available.")

    def _whitelist_item(self, sender, app_data, user_data):
        """Solicita al backend que agregue un item a la lista blanca."""
        identifier = user_data.get('path') or user_data.get('name')
        if identifier:
            self.logger.info(f"Requesting to whitelist item: {identifier}")
            # Esta función debe existir en el app_controller
            success, message = self.app_controller.perform_backend_action('whitelist_item', {'identifier': identifier})
            if success:
                self.logger.info(f"Backend confirmed item whitelisted: {identifier}")
            else:
                self.logger.error(f"Backend failed to whitelist item {identifier}: {message}")
        else:
            self.logger.warning("Cannot whitelist. Identifier not available.")

    def _close_threat_details_modal(self, sender=None, app_data=None):
        """Cierra correctamente el modal de detalles de amenaza."""
        try:
            if dpg.does_item_exist("threat_details_modal"):
                dpg.delete_item("threat_details_modal")
                self.logger.debug("Threat details modal closed successfully")
        except Exception as e:
            self.logger.error(f"Error closing threat details modal: {e}")
            # Forzar limpieza en caso de error
            try:
                dpg.delete_item("threat_details_modal")
            except:
                pass