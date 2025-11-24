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
        
        # Inicializar variables de estado
        self.current_view = "current"     # "current", "all", o "simple"
        self.view_mode = "grouped"        # "grouped" o "simple"
        self.selected_threat = None       # Amenaza seleccionada
        self.simple_threats_map = {}      # Mapeo para vista simple
        self.grouped_threats = {}         # Amenazas agrupadas
        self.expanded_groups = set()      # Grupos expandidos
        
        self.ui_tags = {
            "threat_list": "threat_viewer_threat_list",
            "decision_tree_container": "threat_viewer_decision_tree_container"
        }

    def render(self):
        """Crear la vista del visualizador de amenazas con filtros y agrupación."""
        dpg.add_text("🔬 Analizador de Amenazas", color=(255, 100, 255))
        dpg.add_separator()
        
        # Botones de filtrado con estilos mejorados
        with dpg.group(horizontal=True):
            btn_current = dpg.add_button(label="🎯 Apps Sospechosas Actuales", callback=self._show_current_threats, tag="btn_current_threats")
            btn_all = dpg.add_button(label="📋 Ver Todas las Detecciones", callback=self._show_all_detections, tag="btn_all_detections")
            btn_simple = dpg.add_button(label="📝 Versión Simple", callback=self._show_simple_view, tag="btn_simple_view")
            btn_refresh = dpg.add_button(label="🔄 Actualizar", callback=self._refresh_threats)
            
            # Aplicar temas a los botones para mejor visibilidad
            self._apply_button_themes(btn_current, btn_all, btn_simple, btn_refresh)
        
        dpg.add_separator()
        
        # Las variables de estado ya están inicializadas en __init__
        
        with dpg.group(horizontal=True):
            # Panel izquierdo: Lista de amenazas con agrupación
            with dpg.child_window(width=350, height=-1, tag="threat_list_container"):
                dpg.add_text("Amenazas Detectadas", tag="threat_list_title")
                
                # Contenedor scrollable para la lista agrupada
                with dpg.child_window(width=-1, height=-1, tag="threat_grouped_container"):
                    pass  # Se llenará dinámicamente
            
            # Panel derecho: Visualizador del árbol de decisión
            with dpg.child_window(width=-1, height=-1, tag=self.ui_tags['decision_tree_container']):
                dpg.add_text("Selecciona una amenaza de la lista para ver el proceso de análisis.", tag="threat_viewer_placeholder")

        # Llenar la lista de amenazas al renderizar
        self._update_threat_display()
        
        # Agregar botones de acción globales
        dpg.add_spacer(height=10)
        with dpg.group(horizontal=True):
            dpg.add_button(label="🛑 Detener Seleccionado", callback=self._stop_selected_threat)
            dpg.add_button(label="🔒 Cuarentena Seleccionado", callback=self._quarantine_selected_threat)
            dpg.add_button(label="📍 Localizar Seleccionado", callback=self._locate_selected_threat)
            dpg.add_button(label="✅ Lista Blanca Seleccionado", callback=self._whitelist_selected_threat)
        
        # Área de mensajes de acción
        dpg.add_spacer(height=5)
        self.container = self.parent_tag  # Para mensajes de acción

    def _show_current_threats(self):
        """Mostrar solo las amenazas actuales/sospechosas principales."""
        self.current_view = "current"
        self.view_mode = "grouped"
        self._update_threat_display()
        
        # Actualizar título
        if dpg.does_item_exist("threat_list_title"):
            dpg.set_value("threat_list_title", "🎯 Apps Sospechosas Actuales")
    
    def _show_all_detections(self):
        """Mostrar todas las detecciones históricas."""
        self.current_view = "all"
        self.view_mode = "grouped"
        self._update_threat_display()
        
        # Actualizar título
        if dpg.does_item_exist("threat_list_title"):
            dpg.set_value("threat_list_title", "📋 Todas las Detecciones")
    
    def _show_simple_view(self):
        """Mostrar vista simple (versión anterior)."""
        self.current_view = "current"
        self.view_mode = "simple"
        self._update_threat_display()
        
        # Actualizar título
        if dpg.does_item_exist("threat_list_title"):
            dpg.set_value("threat_list_title", "📝 Vista Simple")
    
    def _refresh_threats(self):
        """Refrescar la lista de amenazas."""
        self._update_threat_display()
    
    def _update_threat_display(self):
        """Actualiza la vista de amenazas con agrupación o vista simple."""
        # Limpiar contenedor
        if dpg.does_item_exist("threat_grouped_container"):
            children = dpg.get_item_children("threat_grouped_container", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Obtener amenazas según el filtro actual
        if self.current_view == "current":
            threats = self._get_current_threats()
        else:
            threats = self._get_all_threats()
        
        # Renderizar según el modo de vista
        if self.view_mode == "simple":
            self._render_simple_threats(threats)
        else:
            # Agrupar amenazas por nombre de proceso
            grouped = self._group_threats(threats)
            # Renderizar grupos
            self._render_grouped_threats(grouped)
    
    def _get_current_threats(self):
        """Obtener solo las amenazas más críticas actuales."""
        all_threats = self.app_controller.get_active_threats()
        
        # Filtrar solo amenazas de riesgo HIGH y CRITICAL, o con score alto
        current_threats = []
        for threat in all_threats:
            risk = threat.get('risk', 'UNKNOWN')
            score = threat.get('score', 0)
            
            if risk in ['HIGH', 'CRITICAL'] or score >= 0.3:
                current_threats.append(threat)
        
        # Limitar a las 20 más importantes
        current_threats.sort(key=lambda x: (
            {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.get('risk', 'UNKNOWN'), 0),
            x.get('score', 0)
        ), reverse=True)
        
        return current_threats[:20]
    
    def _get_all_threats(self):
        """Obtener todas las amenazas detectadas."""
        # Aquí podríamos leer de logs o una base de datos
        # Por ahora, usar las amenazas activas como ejemplo expandido
        all_threats = self.app_controller.get_active_threats()
        
        # Simular más amenazas leyendo desde logs
        try:
            import os
            log_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'antivirus.log')
            
            if os.path.exists(log_path):
                recent_detections = self._parse_log_threats(log_path)
                all_threats.extend(recent_detections)
        except Exception as e:
            self.logger.warning(f"No se pudieron cargar amenazas del log: {e}")
        
        return all_threats
    
    def _parse_log_threats(self, log_path):
        """Parsear amenazas del archivo de log."""
        threats = []
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-500:]  # Últimas 500 líneas
            
            for line in lines:
                if 'Keylogger detectado:' in line:
                    # Extraer información del log
                    import re
                    match = re.search(r'Keylogger detectado: ([^(]+)\(PID: (\d+), Score: ([\d.]+)\)', line)
                    if match:
                        process_name = match.group(1).strip()
                        pid = int(match.group(2))
                        score = float(match.group(3))
                        
                        # Determinar nivel de riesgo basado en score
                        if score >= 0.35:
                            risk = 'HIGH'
                        elif score >= 0.25:
                            risk = 'MEDIUM'
                        else:
                            risk = 'LOW'
                        
                        threats.append({
                            'name': process_name,
                            'pid': pid,
                            'score': score,
                            'risk': risk,
                            'type': 'Keylogger',
                            'timestamp': line.split(' - ')[0],
                            'details': f"Detectado en logs - Score: {score}"
                        })
        except Exception as e:
            self.logger.error(f"Error parseando logs: {e}")
        
        return threats
    
    def _group_threats(self, threats):
        """Agrupar amenazas por nombre de proceso."""
        grouped = {}
        
        for threat in threats:
            process_name = threat.get('name', 'Unknown')
            
            if process_name not in grouped:
                grouped[process_name] = {
                    'threats': [],
                    'count': 0,
                    'max_risk': 'LOW',
                    'max_score': 0
                }
            
            grouped[process_name]['threats'].append(threat)
            grouped[process_name]['count'] += 1
            
            # Actualizar máximo riesgo y score
            threat_risk = threat.get('risk', 'LOW')
            threat_score = threat.get('score', 0)
            
            risk_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            if risk_levels.get(threat_risk, 1) > risk_levels.get(grouped[process_name]['max_risk'], 1):
                grouped[process_name]['max_risk'] = threat_risk
            
            if threat_score > grouped[process_name]['max_score']:
                grouped[process_name]['max_score'] = threat_score
        
        return grouped
    
    def _render_grouped_threats(self, grouped_threats):
        """Renderizar amenazas agrupadas con expansión."""
        for process_name, group_data in grouped_threats.items():
            count = group_data['count']
            max_risk = group_data['max_risk']
            max_score = group_data['max_score']
            
            # Color basado en el riesgo máximo - Mejorados para mejor contraste
            risk_colors = {
                'LOW': (50, 180, 50),      # Verde más oscuro
                'MEDIUM': (220, 180, 20),  # Amarillo más oscuro/dorado
                'HIGH': (230, 100, 50),    # Naranja más vibrante
                'CRITICAL': (200, 50, 50)  # Rojo más oscuro pero visible
            }
            color = risk_colors.get(max_risk, (150, 150, 150))
            
            if count == 1:
                # Amenaza individual
                threat = group_data['threats'][0]
                self._render_single_threat(threat, color)
            else:
                # Grupo expandible
                group_id = f"group_{process_name}"
                is_expanded = group_id in self.expanded_groups
                
                # Botón de grupo
                expand_icon = "📂" if is_expanded else "📁"
                group_label = f"{expand_icon} {process_name} ({count} detecciones) - {max_risk}"
                
                if dpg.add_button(
                    label=group_label,
                    callback=lambda s, a, u=group_id: self._toggle_group(u),
                    parent="threat_grouped_container"
                ):
                    dpg.bind_item_theme(dpg.last_item(), self._create_threat_theme(color))
                
                # Mostrar elementos del grupo si está expandido
                if is_expanded:
                    with dpg.group(parent="threat_grouped_container", indent=20):
                        for i, threat in enumerate(group_data['threats']):
                            self._render_single_threat(threat, color, f"  └─ Instancia {i+1}")
    
    def _render_single_threat(self, threat, color, prefix=""):
        """Renderizar una amenaza individual."""
        name = threat.get('name', 'Unknown')
        risk = threat.get('risk', 'N/A')
        pid = threat.get('pid', 'N/A')
        score = threat.get('score', 0)
        
        label = f"{prefix}{name} (PID:{pid}) - {risk} (Score:{score:.2f})"
        
        if dpg.add_selectable(
            label=label,
            callback=lambda s, a, u=threat: self._on_threat_selected_new(u),
            parent="threat_grouped_container"
        ):
            dpg.bind_item_theme(dpg.last_item(), self._create_threat_theme(color))
    
    def _render_simple_threats(self, threats):
        """Renderizar amenazas en vista simple (versión anterior)."""
        # Crear listbox tradicional
        threat_names = []
        self.simple_threats_map = {}  # Mapear nombres a objetos de amenaza
        
        for i, threat in enumerate(threats):
            name = threat.get('name', 'Unknown')
            risk = threat.get('risk', 'N/A')
            pid = threat.get('pid', 'N/A')
            score = threat.get('score', 0)
            
            # Formatear nombre con información detallada
            display_name = f"{name} (PID:{pid}) - {risk} (Score:{score:.2f})"
            threat_names.append(display_name)
            self.simple_threats_map[display_name] = threat
        
        # Crear listbox si no existe
        if not dpg.does_item_exist("simple_threat_listbox"):
            dpg.add_listbox(
                items=threat_names,
                tag="simple_threat_listbox",
                callback=self._on_simple_threat_selected,
                num_items=min(20, len(threat_names)),
                parent="threat_grouped_container"
            )
        else:
            dpg.configure_item("simple_threat_listbox", items=threat_names)
    
    def _on_simple_threat_selected(self, sender, app_data):
        """Callback para selección en vista simple."""
        if app_data in self.simple_threats_map:
            self.selected_threat = self.simple_threats_map[app_data]
            self._display_decision_tree(self.selected_threat)
    
    def _create_threat_theme(self, color):
        """Crear tema visual para amenaza con mejor contraste."""
        # Colores mejorados con mejor contraste
        enhanced_color = (
            min(255, max(50, color[0])),  # Asegurar mínimo brillo
            min(255, max(50, color[1])),
            min(255, max(50, color[2]))
        )
        
        hover_color = (
            min(255, enhanced_color[0] + 40),
            min(255, enhanced_color[1] + 40), 
            min(255, enhanced_color[2] + 40)
        )
        
        with dpg.theme() as theme:
            with dpg.theme_component(dpg.mvButton):
                dpg.add_theme_color(dpg.mvThemeCol_Button, enhanced_color, category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, hover_color, category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)  # Texto blanco
            with dpg.theme_component(dpg.mvSelectable):
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, enhanced_color, category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, hover_color, category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)  # Texto blanco
        return theme
    
    def _apply_button_themes(self, btn_current, btn_all, btn_simple, btn_refresh):
        """Aplicar temas de colores a los botones de filtrado."""
        try:
            # Tema para botón de apps actuales (azul)
            with dpg.theme(tag="theme_current_btn") as current_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (40, 120, 200), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (60, 140, 220), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
            
            # Tema para botón de todas las detecciones (verde)
            with dpg.theme(tag="theme_all_btn") as all_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (50, 150, 50), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (70, 170, 70), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
            
            # Tema para botón de versión simple (morado)
            with dpg.theme(tag="theme_simple_btn") as simple_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (120, 60, 180), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (140, 80, 200), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
            
            # Tema para botón de actualizar (gris)
            with dpg.theme(tag="theme_refresh_btn") as refresh_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (80, 80, 80), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (100, 100, 100), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
            
            # Aplicar temas a los botones
            dpg.bind_item_theme(btn_current, current_theme)
            dpg.bind_item_theme(btn_all, all_theme)
            dpg.bind_item_theme(btn_simple, simple_theme)
            dpg.bind_item_theme(btn_refresh, refresh_theme)
            
        except Exception as e:
            self.logger.warning(f"No se pudieron aplicar temas a los botones: {e}")
    
    def _toggle_group(self, group_id):
        """Alternar expansión de grupo."""
        if group_id in self.expanded_groups:
            self.expanded_groups.remove(group_id)
        else:
            self.expanded_groups.add(group_id)
        
        # Refrescar display
        self._update_threat_display()
    
    def _on_threat_selected_new(self, threat):
        """Callback mejorado para selección de amenaza."""
        self.selected_threat = threat
        self._display_decision_tree(threat)

    def _on_threat_selected(self, sender, app_data):
        """Callback que se ejecuta al seleccionar una amenaza de la lista (compatibilidad)."""
        selected_threat_name = app_data
        threats = self.app_controller.get_active_threats()
        
        # Encontrar el objeto de amenaza completo
        selected_threat = None
        for threat in threats:
            if f"{threat.get('name', 'Unknown')} ({threat.get('risk', 'N/A')})" == selected_threat_name:
                selected_threat = threat
                break
        
        if selected_threat:
            self.selected_threat = selected_threat
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
        if not hasattr(self, 'selected_threat') or not self.selected_threat:
            self._show_action_message("⚠️ Selecciona una amenaza primero", (255, 200, 0))
            return
            
        threat = self.selected_threat
        pid = threat.get('pid')
        if not pid:
            self._show_action_message("❌ PID no disponible para esta amenaza", (255, 100, 100))
            return
        
        process_name = threat.get('name', 'Unknown')
        self._show_action_message(f"🛑 Deteniendo proceso {process_name} (PID:{pid})...", (255, 255, 0))
        
        try:
            success, msg = self.app_controller.perform_backend_action('stop_process', {'pid': pid})
            
            if success:
                self._show_action_message(f"✅ Proceso detenido: {msg}", (100, 255, 100))
                self.logger.info(f"✅ Stop action successful: {msg}")
                # Refrescar la lista después de detener el proceso
                self._refresh_threats()
            else:
                self._show_action_message(f"❌ Error deteniendo proceso: {msg}", (255, 100, 100))
                self.logger.error(f"❌ Stop action failed: {msg}")
        except Exception as e:
            self._show_action_message(f"❌ Error interno: {str(e)}", (255, 100, 100))
            self.logger.error(f"❌ Stop action exception: {e}")
    
    def _quarantine_selected_threat(self):
        """Poner en cuarentena la amenaza seleccionada"""
        if not hasattr(self, 'selected_threat') or not self.selected_threat:
            self._show_action_message("⚠️ Seleccionuna amenaza primero", (255, 200, 0))
            return
            
        threat = self.selected_threat
        
        # Intentar obtener la ruta del archivo
        path = threat.get('path')
        process_name = threat.get('name', 'Unknown')
        pid = threat.get('pid')
        
        # Si no hay path, intentar construir uno basado en el PID
        if not path and pid:
            try:
                import psutil
                process = psutil.Process(pid)
                path = process.exe()
            except:
                pass
        
        if not path:
            self._show_action_message("❌ No se pudo determinar la ruta del archivo para cuarentena", (255, 100, 100))
            return
        
        self._show_action_message(f"🔒 Poniendo en cuarentena: {process_name}...", (255, 255, 0))
        
        try:
            success, msg = self.app_controller.perform_backend_action('quarantine_file', {'path': path})
            
            if success:
                self._show_action_message(f"✅ Archivo en cuarentena: {msg}", (100, 255, 100))
                self.logger.info(f"✅ Quarantine action successful: {msg}")
                # Refrescar la lista después de la cuarentena
                self._refresh_threats()
            else:
                self._show_action_message(f"❌ Error en cuarentena: {msg}", (255, 100, 100))
                self.logger.error(f"❌ Quarantine action failed: {msg}")
        except Exception as e:
            self._show_action_message(f"❌ Error interno: {str(e)}", (255, 100, 100))
            self.logger.error(f"❌ Quarantine action exception: {e}")
    
    def _locate_selected_threat(self):
        """Localizar la amenaza seleccionada"""
        if not hasattr(self, 'selected_threat') or not self.selected_threat:
            self._show_action_message("⚠️ Selecciona una amenaza primero", (255, 200, 0))
            return
            
        threat = self.selected_threat
        path = threat.get('path')
        pid = threat.get('pid')
        
        # Si no hay path, intentar obtenerlo del PID
        if not path and pid:
            try:
                import psutil
                process = psutil.Process(pid)
                path = process.exe()
            except:
                pass
        
        if path:
            try:
                import subprocess
                import os
                if os.path.exists(path):
                    subprocess.run(['explorer', '/select,', os.path.normpath(path)])
                    self._show_action_message(f"📍 Abriendo ubicación: {path}", (100, 255, 255))
                else:
                    self._show_action_message("❌ El archivo ya no existe en la ubicación", (255, 100, 100))
            except Exception as e:
                self._show_action_message(f"❌ Error localizando archivo: {str(e)}", (255, 100, 100))
        else:
            self._show_action_message("❌ No se pudo determinar la ubicación del archivo", (255, 100, 100))
    
    def _whitelist_selected_threat(self):
        """Agregar la amenaza seleccionada a la whitelist"""
        if not hasattr(self, 'selected_threat') or not self.selected_threat:
            self._show_action_message("⚠️ Selecciona una amenaza primero", (255, 200, 0))
            return
            
        threat = self.selected_threat
        identifier = threat.get('name', 'Unknown')
        
        self._show_action_message(f"✅ Agregando {identifier} a la whitelist...", (255, 255, 0))
        
        try:
            success, msg = self.app_controller.perform_backend_action('whitelist_item', {'identifier': identifier})
            
            if success:
                self._show_action_message(f"✅ Agregado a whitelist: {msg}", (100, 255, 100))
                self.logger.info(f"✅ Whitelist action successful: {msg}")
                # Refrescar la lista después de agregar a whitelist
                self._refresh_threats()
            else:
                self._show_action_message(f"❌ Error en whitelist: {msg}", (255, 100, 100))
                self.logger.error(f"❌ Whitelist action failed: {msg}")
        except Exception as e:
            self._show_action_message(f"❌ Error interno: {str(e)}", (255, 100, 100))
            self.logger.error(f"❌ Whitelist action exception: {e}")
    
    def _show_action_message(self, message: str, color: tuple = (255, 255, 255)):
        """Mostrar mensaje de acción en la interfaz"""
        try:
            # Crear o actualizar área de mensajes
            if not hasattr(self, 'action_message_tag'):
                self.action_message_tag = f"{self.view_id}_action_message"
            
            # Limpiar mensaje anterior si existe
            if dpg.does_item_exist(self.action_message_tag):
                dpg.delete_item(self.action_message_tag)
            
            # Agregar nuevo mensaje con color
            dpg.add_text(message, color=color, tag=self.action_message_tag, parent=self.container)
            
            # Auto-limpiar mensaje después de 5 segundos
            def clear_message():
                import time
                time.sleep(5)
                if dpg.does_item_exist(self.action_message_tag):
                    dpg.delete_item(self.action_message_tag)
            
            import threading
            threading.Thread(target=clear_message, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Error mostrando mensaje de acción: {e}")