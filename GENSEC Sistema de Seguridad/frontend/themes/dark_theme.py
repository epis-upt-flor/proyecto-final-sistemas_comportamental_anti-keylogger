"""
Tema Oscuro Profesional para Dear PyGui
======================================

Configuración de colores y estilos para una apariencia moderna y profesional.
Optimizado para aplicaciones de seguridad y monitoreo.
"""

import dearpygui.dearpygui as dpg


def apply_dark_theme():
    """
    Aplicar tema oscuro profesional
    
    Esquema de colores:
    - Fondo principal: Gris oscuro
    - Acentos: Azul cibernético 
    - Alertas: Rojo/Naranja
    - Éxito: Verde
    - Texto: Blanco/Gris claro
    """
    
    # Colores base del tema
    COLORS = {
        # Fondos
        'bg_primary': (25, 25, 25, 255),      # Fondo principal muy oscuro
        'bg_secondary': (35, 35, 35, 255),    # Fondo secundario
        'bg_tertiary': (45, 45, 45, 255),     # Fondo de paneles
        
        # Acentos
        'accent_blue': (0, 150, 255, 255),    # Azul cibernético principal
        'accent_blue_hover': (30, 180, 255, 255),  # Azul hover
        'accent_blue_active': (0, 120, 200, 255),  # Azul activo
        
        # Estados
        'success': (0, 255, 100, 255),        # Verde éxito
        'warning': (255, 165, 0, 255),        # Naranja advertencia
        'danger': (255, 50, 50, 255),         # Rojo peligro
        'info': (100, 200, 255, 255),         # Azul información
        
        # Texto
        'text_primary': (255, 255, 255, 255),   # Texto principal blanco
        'text_secondary': (200, 200, 200, 255), # Texto secundario gris claro
        'text_disabled': (120, 120, 120, 255),  # Texto deshabilitado
        
        # Bordes
        'border': (80, 80, 80, 255),          # Bordes sutiles
        'border_active': (0, 150, 255, 255),  # Bordes activos
    }
    
    # Configurar tema global
    with dpg.theme() as global_theme:
        
        # === VENTANAS Y CONTENEDORES ===
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, COLORS['bg_primary'])
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_PopupBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, COLORS['bg_secondary'])
            
            # Bordes
            dpg.add_theme_color(dpg.mvThemeCol_Border, COLORS['border'])
            dpg.add_theme_color(dpg.mvThemeCol_BorderShadow, (0, 0, 0, 0))
            
            # Texto
            dpg.add_theme_color(dpg.mvThemeCol_Text, COLORS['text_primary'])
            dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, COLORS['text_disabled'])
            
            # Scrollbars
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, COLORS['accent_blue_hover'])
            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, COLORS['accent_blue_active'])
        
        # === BOTONES ===
        with dpg.theme_component(dpg.mvButton):
            dpg.add_theme_color(dpg.mvThemeCol_Button, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, COLORS['accent_blue_hover'])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, COLORS['accent_blue_active'])
            dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255, 255))
            
            # Estilo de botones
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5)
            dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 10, 8)
        
        # === TABS ===
        with dpg.theme_component(dpg.mvTabBar):
            dpg.add_theme_color(dpg.mvThemeCol_Tab, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_TabHovered, COLORS['accent_blue_hover'])
            dpg.add_theme_color(dpg.mvThemeCol_TabActive, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocused, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_TabUnfocusedActive, COLORS['bg_secondary'])
        
        # === INPUTS ===
        with dpg.theme_component(dpg.mvInputText):
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, COLORS['bg_primary'])
            dpg.add_theme_color(dpg.mvThemeCol_Border, COLORS['border'])
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3)
        
        # === CHECKBOXES ===
        with dpg.theme_component(dpg.mvCheckbox):
            dpg.add_theme_color(dpg.mvThemeCol_CheckMark, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, COLORS['accent_blue_active'])
        
        # === SLIDERS ===
        with dpg.theme_component(dpg.mvSliderFloat):
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, COLORS['bg_primary'])
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, COLORS['accent_blue_active'])
        
        # === HEADERS/COLLAPSIBLE ===
        with dpg.theme_component(dpg.mvCollapsingHeader):
            dpg.add_theme_color(dpg.mvThemeCol_Header, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, COLORS['accent_blue_hover'])
            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, COLORS['accent_blue'])
        
        # === SEPARADORES ===
        with dpg.theme_component(dpg.mvSeparator):
            dpg.add_theme_color(dpg.mvThemeCol_Separator, COLORS['border'])
            dpg.add_theme_color(dpg.mvThemeCol_SeparatorHovered, COLORS['accent_blue'])
            dpg.add_theme_color(dpg.mvThemeCol_SeparatorActive, COLORS['accent_blue_active'])
        
        # === PROGRESS BARS ===
        with dpg.theme_component(dpg.mvProgressBar):
            dpg.add_theme_color(dpg.mvThemeCol_FrameBg, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_PlotHistogram, COLORS['accent_blue'])
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3)
        
        # === MENÚS ===
        with dpg.theme_component(dpg.mvMenuBar):
            dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg, COLORS['bg_secondary'])
            dpg.add_theme_color(dpg.mvThemeCol_Header, COLORS['bg_tertiary'])
            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, COLORS['accent_blue_hover'])
            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, COLORS['accent_blue'])
    
    # Aplicar tema globalmente
    dpg.bind_theme(global_theme)


def apply_success_theme():
    """Tema verde para elementos de éxito"""
    with dpg.theme() as success_theme:
        with dpg.theme_component(dpg.mvButton):
            dpg.add_theme_color(dpg.mvThemeCol_Button, (0, 200, 80, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (0, 220, 100, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (0, 180, 60, 255))
    return success_theme


def apply_danger_theme():
    """Tema rojo para elementos de peligro"""
    with dpg.theme() as danger_theme:
        with dpg.theme_component(dpg.mvButton):
            dpg.add_theme_color(dpg.mvThemeCol_Button, (220, 50, 50, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (240, 70, 70, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (200, 30, 30, 255))
    return danger_theme


def apply_warning_theme():
    """Tema naranja para elementos de advertencia"""
    with dpg.theme() as warning_theme:
        with dpg.theme_component(dpg.mvButton):
            dpg.add_theme_color(dpg.mvThemeCol_Button, (255, 140, 0, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (255, 160, 30, 255))
            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (230, 120, 0, 255))
    return warning_theme


# Colores predefinidos para uso directo
CYBER_COLORS = {
    'blue': (0, 150, 255),
    'green': (0, 255, 100),
    'red': (255, 50, 50),
    'orange': (255, 165, 0),
    'purple': (150, 50, 255),
    'cyan': (0, 255, 255),
    'yellow': (255, 255, 0),
    'white': (255, 255, 255),
    'gray': (150, 150, 150),
    'dark_gray': (80, 80, 80)
}


def get_threat_level_color(level: str) -> tuple:
    """
    Obtener color según nivel de amenaza
    
    Args:
        level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    
    Returns:
        Tupla RGB del color correspondiente
    """
    colors = {
        'LOW': CYBER_COLORS['green'],
        'MEDIUM': CYBER_COLORS['orange'], 
        'HIGH': CYBER_COLORS['red'],
        'CRITICAL': (255, 0, 0),  # Rojo intenso
        'NORMAL': CYBER_COLORS['gray'],
        'UNKNOWN': CYBER_COLORS['purple']
    }
    return colors.get(level.upper(), CYBER_COLORS['gray'])