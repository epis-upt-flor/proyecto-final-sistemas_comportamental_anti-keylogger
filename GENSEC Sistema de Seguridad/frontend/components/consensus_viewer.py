"""
Componente Consensus Viewer - Detalle de Ponderación
====================================================

Visualizador detallado de la lógica de consenso, mostrando cómo se calculó
el puntaje de riesgo final, los pesos de cada detector y si se activó el veto.
"""

import dearpygui.dearpygui as dpg
import logging
from typing import Dict, Any

class ConsensusViewerComponent:
    """
    Componente para visualizar el detalle de la ponderación de consenso.
    """
    
    def __init__(self, parent_tag: str, app_controller):
        """
        Args:
            parent_tag: Tag del contenedor padre.
            app_controller: Controlador principal de la UI.
        """
        self.parent_tag = parent_tag
        self.app_controller = app_controller
        self.logger = logging.getLogger("ConsensusViewer")
        self.selected_threat = None
        
        self.ui_tags = {
            "score_indicator": "consensus_score_indicator",
            "weights_table": "consensus_weights_table",
            "veto_section": "consensus_veto_section",
            "details_group": "consensus_details_group"
        }

    def render(self):
        """Crear la vista del visor de consenso."""
        # Limpiar vista anterior si existe
        if dpg.does_item_exist(self.parent_tag):
            dpg.delete_item(self.parent_tag)

        with dpg.group(tag=self.parent_tag, parent="content_area"):
            dpg.add_text("⚖️ Consensus Weighting Detail", color=(255, 200, 0))
            dpg.add_separator()
            
            # Botón para volver atrás (si es necesario, aunque la navegación suele ser por tabs)
            dpg.add_button(label="⬅ Back to Monitor", callback=self._go_back)
            dpg.add_spacer(height=10)
            
            # Contenedor principal
            with dpg.group(tag=self.ui_tags['details_group']):
                dpg.add_text("Select a threat from the Live TTPs Log to view details.", color=(150, 150, 150))

    def update_view(self, threat_data: Dict[str, Any]):
        """Actualizar la vista con los datos de una amenaza específica."""
        self.selected_threat = threat_data
        
        # Limpiar vista anterior
        dpg.delete_item(self.ui_tags['details_group'], children_only=True)
        
        if not threat_data:
            dpg.add_text("No threat selected.", parent=self.ui_tags['details_group'])
            return

        # Extraer datos
        name = threat_data.get('name', 'Unknown')
        pid = threat_data.get('pid', 'N/A')
        final_score = threat_data.get('score', 0.0)
        risk = threat_data.get('risk', 'LOW')
        
        # 1. Encabezado de la Amenaza
        with dpg.group(parent=self.ui_tags['details_group']):
            dpg.add_text(f"Process: {name} (PID: {pid})", color=(255, 255, 255))
            dpg.add_spacer(height=5)
        
        # 2. Score Final de Riesgo
        with dpg.group(horizontal=True, parent=self.ui_tags['details_group']):
            with dpg.child_window(width=200, height=100, border=True):
                dpg.add_text("Final Risk Score", color=(200, 200, 200))
                dpg.add_spacer(height=10)
                
                # Color del score
                score_color = (0, 255, 0)
                if final_score >= 0.7: score_color = (255, 0, 0)
                elif final_score >= 0.4: score_color = (255, 165, 0)
                
                dpg.add_text(f"{final_score:.2f}", color=score_color)
                dpg.add_text(f"Risk Level: {risk}", color=score_color)

            # 3. Sección de Veto (Prominente)
            # Simular lógica de veto para la UI si no viene explícita
            veto_active = False
            veto_reason = ""
            
            # Si el ML tiene confianza alta de ser seguro pero hay alertas heurísticas
            # Esto es una simulación visual basada en la lógica del backend
            if risk == "LOW" and threat_data.get('ml_confidence', 0) > 0.8:
                veto_active = True
                veto_reason = "ML High Confidence Safe"
            
            # O si viene explícito en los metadatos
            if threat_data.get('veto_active'):
                veto_active = True
                veto_reason = threat_data.get('veto_reason', 'Unknown')

            if veto_active:
                with dpg.child_window(width=300, height=100, border=True):
                    dpg.add_text("🛡️ VETO LOGIC ACTIVE", color=(0, 255, 255))
                    dpg.add_separator()
                    dpg.add_text("Heuristics Overridden", color=(200, 200, 200))
                    dpg.add_text(f"Reason: {veto_reason}", color=(255, 255, 0), wrap=280)
            
        dpg.add_spacer(height=20, parent=self.ui_tags['details_group'])
        
        # 4. Tabla de Ponderación
        dpg.add_text("📊 Detector Weighting Breakdown", color=(255, 200, 0), parent=self.ui_tags['details_group'])
        
        with dpg.table(header_row=True, parent=self.ui_tags['details_group'], 
                       borders_innerH=True, borders_outerH=True, borders_innerV=True, borders_outerV=True):
            dpg.add_table_column(label="Detector Module")
            dpg.add_table_column(label="Individual Score")
            dpg.add_table_column(label="Applied Weight")
            dpg.add_table_column(label="Final Contribution")
            
            # Simular desglose de detectores basado en el tipo de amenaza
            # En un sistema real, esto vendría del backend
            detectors = self._simulate_detector_breakdown(threat_data)
            
            for det in detectors:
                with dpg.table_row():
                    dpg.add_text(det['name'])
                    dpg.add_text(f"{det['score']:.2f}")
                    dpg.add_text(f"{det['weight']:.2f}")
                    
                    contrib = det['score'] * det['weight']
                    dpg.add_text(f"{contrib:.2f}", color=(200, 200, 200))

    def _simulate_detector_breakdown(self, threat):
        """
        Simula el desglose de puntajes para la visualización.
        Refleja los pesos definidos en el backend: ML(0.7), Keylogger(0.3), etc.
        """
        t_type = threat.get('type', 'Unknown').lower()
        base_score = threat.get('score', 0.0)
        
        detectors = []
        
        # ML Detector (Peso 0.7)
        ml_score = base_score
        if 'ml' in t_type or 'keylogger' in t_type:
            ml_score = min(1.0, base_score * 1.1)
        
        detectors.append({
            'name': 'ML Detector (ONNX)',
            'score': ml_score,
            'weight': 0.7
        })
        
        # Keylogger Detector (Peso 0.3)
        kl_score = 0.0
        if 'keylogger' in t_type:
            kl_score = base_score
        
        detectors.append({
            'name': 'Keylogger Heuristics',
            'score': kl_score,
            'weight': 0.3
        })
        
        # Behavior Detector (Peso 0.4 - Auxiliar)
        beh_score = 0.0
        if 'behavior' in t_type:
            beh_score = base_score
            
        detectors.append({
            'name': 'Behavior Analysis',
            'score': beh_score,
            'weight': 0.4
        })
        
        return detectors

    def _go_back(self, sender, app_data):
        """Volver a la vista de monitor."""
        if hasattr(self.app_controller, 'show_realtime_monitor'):
            self.app_controller.show_realtime_monitor()
