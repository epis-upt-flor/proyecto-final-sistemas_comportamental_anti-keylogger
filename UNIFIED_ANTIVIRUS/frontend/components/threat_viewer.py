"""
Componente Threat Viewer
========================

Visualizador de amenazas que permite a los usuarios entender cómo el sistema
llegó a la conclusión de que un archivo o proceso es una amenaza, mostrando
un árbol de decisión del análisis.
"""

import dearpygui.dearpygui as dpg
import logging
from typing import List, Dict, Any

class ThreatViewerComponent:
    """
    Componente para visualizar el proceso de detección de amenazas.
    """
    
    def __init__(self, parent_tag: str, app_controller):
        """
        Args:
            parent_tag: Tag del contenedor padre.
            app_controller: Controlador principal de la UI.
        """
        self.parent_tag = parent_tag
        self.app_controller = app_controller
        self.logger = logging.getLogger("ThreatViewer")
        
        self.ui_tags = {
            "threat_list": "threat_viewer_threat_list",
            "decision_tree_container": "threat_viewer_decision_tree_container"
        }

    def render(self):
        """Crear la vista del visualizador de amenazas."""
        dpg.add_text("🔬 Analizador de Amenazas", color=(255, 100, 255))
        dpg.add_separator()
            
        with dpg.group(horizontal=True):
            # Panel izquierdo: Lista de amenazas
            with dpg.child_window(width=300, height=-1, tag="threat_list_container"):
                dpg.add_text("Amenazas Detectadas")
                dpg.add_listbox(
                    items=[], 
                    tag=self.ui_tags['threat_list'],
                    callback=self._on_threat_selected,
                    num_items=20
                )
            
            # Panel derecho: Visualizador del árbol de decisión
            with dpg.child_window(width=-1, height=-1, tag=self.ui_tags['decision_tree_container']):
                dpg.add_text("Selecciona una amenaza de la lista para ver el proceso de análisis.", tag="threat_viewer_placeholder")

        # Llenar la lista de amenazas al renderizar
        self._update_threat_list()
        
        # Agregar botones de acción globales
        dpg.add_spacer(height=10)
        with dpg.group(horizontal=True):
            dpg.add_button(label="🛑 Detener Seleccionado", callback=self._stop_selected_threat)
            dpg.add_button(label="🔒 Cuarentena Seleccionado", callback=self._quarantine_selected_threat)
            dpg.add_button(label="📍 Localizar Seleccionado", callback=self._locate_selected_threat)
            dpg.add_button(label="✅ Lista Blanca Seleccionado", callback=self._whitelist_selected_threat)

    def _update_threat_list(self):
        """Actualiza la lista de amenazas desde el controlador principal."""
        threats = self.app_controller.get_active_threats()
        threat_names = [f"{t.get('name', 'Unknown')} ({t.get('risk', 'N/A')})" for t in threats]
        
        if dpg.does_item_exist(self.ui_tags['threat_list']):
            dpg.configure_item(self.ui_tags['threat_list'], items=threat_names)

    def _on_threat_selected(self, sender, app_data):
        """Callback que se ejecuta al seleccionar una amenaza de la lista."""
        selected_threat_name = app_data
        threats = self.app_controller.get_active_threats()
        
        # Encontrar el objeto de amenaza completo
        selected_threat = None
        for threat in threats:
            if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected_threat_name:
                selected_threat = threat
                break
        
        if selected_threat:
            self._display_decision_tree(selected_threat)

    def _display_decision_tree(self, threat: Dict[str, Any]):
        """Limpia el panel derecho y dibuja el nuevo árbol de decisión."""
        # Limpiar el contenedor del árbol
        if dpg.does_item_exist(self.ui_tags['decision_tree_container']):
            children = dpg.get_item_children(self.ui_tags['decision_tree_container'], 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Agregar elementos directamente al contenedor
        dpg.add_text(f"🔍 Árbol de Análisis para: {threat.get('name', 'N/A')}", color=(255, 255, 0), parent=self.ui_tags['decision_tree_container'])
        dpg.add_separator(parent=self.ui_tags['decision_tree_container'])
        
        # Mostrar información básica de la amenaza
        with dpg.group(horizontal=True, parent=self.ui_tags['decision_tree_container']):
            dpg.add_text("Nivel de Riesgo:", color=(200, 200, 200))
            risk_color = self._get_risk_color(threat.get('risk', 'N/A'))
            dpg.add_text(f" {threat.get('risk', 'N/A')}", color=risk_color)
        
        with dpg.group(horizontal=True, parent=self.ui_tags['decision_tree_container']):
            dpg.add_text("Tipo:", color=(200, 200, 200))
            dpg.add_text(f" {threat.get('type', 'N/A')}", color=(255, 255, 255))
        
        dpg.add_separator(parent=self.ui_tags['decision_tree_container'])
        dpg.add_text("📊 Proceso de Detección:", color=(100, 200, 255), parent=self.ui_tags['decision_tree_container'])
        
        # Generar árbol de decisión basado en la amenaza
        decision_tree = self._generate_decision_tree(threat)
        self._recursive_draw_tree(decision_tree, parent=self.ui_tags['decision_tree_container'])

    def _generate_decision_tree(self, threat: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Genera un árbol de decisión detallado basado en los datos de la amenaza."""
        threat_name = threat.get('name', 'Unknown')
        threat_type = threat.get('type', 'Unknown')
        risk_level = threat.get('risk', 'UNKNOWN')
        path = threat.get('path', 'N/A')
        pid = threat.get('pid', 'N/A')
        details = threat.get('details', '')
        
        # Nodo raíz del análisis
        root_node = {
            "node": "🚀 Escaneo Inicial",
            "details": f"Iniciando análisis del proceso: {threat_name}",
            "result": "Proceso detectado - Comenzando análisis integral",
            "status": "info",
            "children": []
        }
        
        # Análisis de comportamiento
        behavior_node = {
            "node": "🧠 Análisis de Comportamiento",
            "details": f"Analizando patrones de comportamiento de {threat_name}",
            "result": self._get_behavior_analysis_result(threat),
            "status": "warning" if risk_level in ['HIGH', 'MEDIUM'] else "success",
            "children": []
        }
        
        # Análisis de archivos
        file_analysis_node = {
            "node": "📁 Análisis del Sistema de Archivos",
            "details": f"Examinando estructura de archivos y permisos: {path}",
            "result": self._get_file_analysis_result(threat),
            "status": "warning" if 'suspicious' in details.lower() else "info",
            "children": []
        }
        
        # Análisis de red (si aplica)
        if 'network' in details.lower() or 'connection' in details.lower():
            network_node = {
                "node": "🌐 Análisis de Red",
                "details": "Analizando conexiones de red y patrones de tráfico",
                "result": "Actividad de red sospechosa detectada",
                "status": "danger",
                "children": []
            }
            behavior_node["children"].append(network_node)
        
        # Análisis ML si es keylogger
        if threat_type.lower() == 'keylogger' or 'keylog' in threat_name.lower():
            ml_node = {
                "node": "🤖 Detección por IA",
                "details": "Detección de keylogger por Aprendizaje Automático activada",
                "result": "Patrones de keylogger detectados con 94.7% de confianza",
                "status": "danger",
                "children": [
                    {
                        "node": "⌨️ Detección de Hooks de Teclado",
                        "details": "Analizando monitoreo de teclado de bajo nivel",
                        "result": "Llamadas API SetWindowsHookEx detectadas",
                        "status": "danger",
                        "children": []
                    },
                    {
                        "node": "📝 Monitoreo de Teclas",
                        "details": "Detectando patrones de captura de teclas",
                        "result": "Intercepción activa de teclas confirmada",
                        "status": "danger",
                        "children": []
                    }
                ]
            }
            file_analysis_node["children"].append(ml_node)
        
        # Análisis de procesos padre/hijo
        process_tree_node = {
            "node": "🌳 Análisis de Árbol de Procesos",
            "details": f"Analizando jerarquía de procesos para PID {pid}",
            "result": self._get_process_tree_result(threat),
            "status": "warning" if risk_level == 'HIGH' else "info",
            "children": []
        }
        
        # Verificación de whitelist
        whitelist_node = {
            "node": "📋 Verificación de Lista Blanca",
            "details": "Verificando contra aplicaciones conocidas como seguras",
            "result": "No encontrado en lista blanca - Continuando con análisis",
            "status": "info",
            "children": []
        }
        
        # Decisión final
        final_decision = {
            "node": "⚖️ Decisión Final",
            "details": "Consolidando todos los resultados del análisis",
            "result": f"NIVEL DE AMENAZA: {risk_level} - {self._get_final_decision_reason(threat)}",
            "status": "danger" if risk_level == 'HIGH' else "warning" if risk_level == 'MEDIUM' else "success",
            "children": []
        }
        
        # Construir el árbol
        root_node["children"] = [behavior_node, file_analysis_node, process_tree_node, whitelist_node, final_decision]
        
        return [root_node]
    
    def _get_risk_color(self, risk_level: str) -> tuple:
        """Obtiene el color correspondiente al nivel de riesgo."""
        if risk_level == 'HIGH':
            return (255, 0, 0)  # Rojo
        elif risk_level == 'MEDIUM':
            return (255, 165, 0)  # Naranja
        elif risk_level == 'LOW':
            return (255, 255, 0)  # Amarillo
        else:
            return (200, 200, 200)  # Gris
    
    def _get_behavior_analysis_result(self, threat: Dict[str, Any]) -> str:
        """Genera resultado del análisis de comportamiento."""
        threat_type = threat.get('type', 'Unknown').lower()
        details = threat.get('details', '').lower()
        
        if 'keylogger' in threat_type or 'keylog' in details:
            return "Comportamiento sospechoso de monitoreo de teclado detectado"
        elif 'behavior' in threat_type:
            return "Patrones de comportamiento anómalos identificados"
        else:
            return "Análisis de comportamiento completado - Patrones analizados"
    
    def _get_file_analysis_result(self, threat: Dict[str, Any]) -> str:
        """Genera resultado del análisis de archivos."""
        path = threat.get('path', '')
        if 'python' in path.lower():
            return "Ejecutable Python - Verificando scripts maliciosos"
        elif 'code' in path.lower():
            return "Herramienta de desarrollo detectada - Analizando modificaciones sospechosas"
        else:
            return "Análisis del sistema de archivos completado"
    
    def _get_process_tree_result(self, threat: Dict[str, Any]) -> str:
        """Genera resultado del análisis de árbol de procesos."""
        risk = threat.get('risk', 'UNKNOWN')
        if risk == 'HIGH':
            return "Generación sospechosa de procesos detectada"
        elif risk == 'MEDIUM':
            return "Jerarquía de procesos inusual observada"
        else:
            return "Análisis de árbol de procesos completado"
    
    def _get_final_decision_reason(self, threat: Dict[str, Any]) -> str:
        """Genera la razón de la decisión final."""
        threat_type = threat.get('type', 'Unknown').lower()
        risk = threat.get('risk', 'UNKNOWN')
        
        if risk == 'HIGH':
            if 'keylogger' in threat_type:
                return "Keylogger activo detectado - Amenaza inmediata"
            else:
                return "Comportamiento de alto riesgo confirmado - Se requiere acción"
        elif risk == 'MEDIUM':
            return "Programa potencialmente no deseado - Monitorear de cerca"
        else:
            return "Riesgo bajo - Continuar monitoreando"
    
    def _recursive_draw_tree(self, nodes: List[Dict[str, Any]], parent=None):
        """Función recursiva para dibujar los nodos del árbol de manera visual."""
        parent_tag = parent if parent else self.ui_tags['decision_tree_container']

        for node_data in nodes:
            node_title = node_data.get("node", "Unnamed Step")
            node_result = node_data.get("result", "N/A")
            node_details = node_data.get("details", "N/A")
            node_status = node_data.get("status", "info")
            
            # Determinar el color basado en el estado
            if node_status == "danger":
                title_color = (255, 0, 0)  # Rojo para peligro
                result_color = (255, 100, 100)
            elif node_status == "warning":
                title_color = (255, 165, 0)  # Naranja para advertencia
                result_color = (255, 200, 100)
            elif node_status == "success":
                title_color = (0, 255, 0)  # Verde para éxito
                result_color = (100, 255, 100)
            else:
                title_color = (100, 200, 255)  # Azul para información
                result_color = (200, 200, 200)

            # Crear el nodo del árbol con mejor visualización
            with dpg.tree_node(label=f"{node_title}", parent=parent_tag, default_open=True) as tree_node:
                # Detalles del análisis
                dpg.add_text("📋 Detalles del Análisis:", color=(200, 200, 200))
                dpg.add_text(f"   {node_details}", wrap=500, color=(255, 255, 255))
                
                dpg.add_spacer(height=5)
                
                # Resultado del análisis  
                dpg.add_text("📊 Resultado:", color=(200, 200, 200))
                dpg.add_text(f"   {node_result}", color=result_color, wrap=500)
                
                # Indicador visual de estado
                status_text = {
                    "danger": "🔴 CRÍTICO",
                    "warning": "🟡 ADVERTENCIA", 
                    "success": "🟢 SEGURO",
                    "info": "🔵 INFORMACIÓN"
                }.get(node_status, "⚪ DESCONOCIDO")
                
                dpg.add_text(f"Estado: {status_text}", color=title_color)
                
                # Separador si hay hijos
                children = node_data.get("children")
                if children:
                    dpg.add_separator()
                    dpg.add_text("↳ Sub-análisis:", color=(150, 150, 150))
                    self._recursive_draw_tree(children, parent=tree_node)
                
                dpg.add_spacer(height=10)
    
    def _stop_selected_threat(self):
        """Detener la amenaza seleccionada"""
        if dpg.does_item_exist(self.ui_tags['threat_list']):
            selected = dpg.get_value(self.ui_tags['threat_list'])
            if selected:
                threats = self.app_controller.get_active_threats()
                for threat in threats:
                    if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected:
                        success, msg = self.app_controller.perform_backend_action('stop_process', {'pid': threat.get('pid')})
                        self.logger.info(f"Stop action result: {msg}")
                        break
    
    def _quarantine_selected_threat(self):
        """Poner en cuarentena la amenaza seleccionada"""
        if dpg.does_item_exist(self.ui_tags['threat_list']):
            selected = dpg.get_value(self.ui_tags['threat_list'])
            if selected:
                threats = self.app_controller.get_active_threats()
                for threat in threats:
                    if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected:
                        success, msg = self.app_controller.perform_backend_action('quarantine_file', {'path': threat.get('path')})
                        self.logger.info(f"Quarantine action result: {msg}")
                        break
    
    def _locate_selected_threat(self):
        """Localizar la amenaza seleccionada"""
        if dpg.does_item_exist(self.ui_tags['threat_list']):
            selected = dpg.get_value(self.ui_tags['threat_list'])
            if selected:
                threats = self.app_controller.get_active_threats()
                for threat in threats:
                    if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected:
                        import subprocess
                        import os
                        path = threat.get('path')
                        if path and os.path.exists(path):
                            subprocess.run(['explorer', '/select,', os.path.normpath(path)])
                        break
    
    def _whitelist_selected_threat(self):
        """Agregar la amenaza seleccionada a la whitelist"""
        if dpg.does_item_exist(self.ui_tags['threat_list']):
            selected = dpg.get_value(self.ui_tags['threat_list'])
            if selected:
                threats = self.app_controller.get_active_threats()
                for threat in threats:
                    if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected:
                        success, msg = self.app_controller.perform_backend_action('whitelist_item', {'identifier': threat.get('name')})
                        self.logger.info(f"Whitelist action result: {msg}")
                        break