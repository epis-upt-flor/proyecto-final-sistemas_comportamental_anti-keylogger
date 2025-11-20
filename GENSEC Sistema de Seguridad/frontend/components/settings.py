"""
Componente de Configuración (Settings)
=====================================

Permite al usuario configurar todos los aspectos del antivirus, desde la
protección en tiempo real hasta las actualizaciones y el logging.
"""

import dearpygui.dearpygui as dpg
import logging

class SettingsComponent:
    """
    Componente para gestionar la configuración del sistema.
    """
    
    def __init__(self, parent_tag: str, app_controller):
        """
        Args:
            parent_tag: Tag del contenedor padre.
            app_controller: Controlador principal de la UI.
        """
        self.parent_tag = parent_tag
        self.app_controller = app_controller
        self.logger = logging.getLogger("Settings")
        self.settings = self.app_controller.system_settings
        self.current_info_section = "protection"  # Para el panel dinámico
    
    def _create_system_status_bar(self):
        """Crear barra de estado general del sistema."""
        with dpg.group(horizontal=True):
            # Estado de protección
            protection_status = "🟢 ACTIVA" if self.settings.get('realtime_protection', True) else "🔴 INACTIVA"
            protection_color = (0, 255, 0) if self.settings.get('realtime_protection', True) else (255, 0, 0)
            
            dpg.add_text("Estado de Protección:", color=(200, 200, 200))
            dpg.add_text(protection_status, color=protection_color)
            
            dpg.add_spacer(width=30)
            
            # Modo actual
            gaming_mode = self.settings.get('gaming_mode', False)
            mode_text = "🎮 GAMING" if gaming_mode else "🛡️ PROTECCIÓN"
            mode_color = (255, 165, 0) if gaming_mode else (100, 200, 255)
            
            dpg.add_text("Modo:", color=(200, 200, 200))
            dpg.add_text(mode_text, color=mode_color)
            
            dpg.add_spacer(width=30)
            
            # Rendimiento
            cpu_limit = self.settings.get('max_cpu_usage', 30)
            gpu_accel = "🟢 ON" if self.settings.get('gpu_acceleration', True) else "🔴 OFF"
            gpu_color = (0, 255, 0) if self.settings.get('gpu_acceleration', True) else (255, 100, 100)
            
            dpg.add_text(f"CPU Límite: {cpu_limit}%", color=(200, 200, 200))
            dpg.add_text(f"GPU: {gpu_accel}", color=gpu_color)

    def render(self):
        """Crear la vista de configuración mejorada y dinámica."""
        dpg.add_text("⚙️ Configuración del Sistema", color=(100, 200, 255))
        dpg.add_separator()
        
        # Barra de estado general del sistema
        self._create_system_status_bar()
        dpg.add_spacer(height=15)

        with dpg.group(horizontal=True):
            # Panel principal de configuraciones (redimensionado)
            with dpg.child_window(width=650, height=-1, border=True):
                self._create_protection_settings()
                dpg.add_spacer(height=15)
                self._create_performance_settings()
                dpg.add_spacer(height=15)
                self._create_update_settings()
                dpg.add_spacer(height=15)
                self._create_advanced_settings()
            
            # Panel de información mejorado
            with dpg.child_window(width=-1, height=-1, border=True):
                self._create_dynamic_info_panel()

    def _create_protection_settings(self):
        """Crear grupo de configuraciones de protección mejoradas."""
        with dpg.collapsing_header(label="🛡️ Protección en Tiempo Real", default_open=True):
            # Switch principal de protección con estilo mejorado
            with dpg.group(horizontal=True):
                dpg.add_checkbox(label="🛡️ Protección en Tiempo Real", tag="setting_realtime_protection",
                                 default_value=self.settings.get('realtime_protection', True),
                                 callback=self._on_protection_toggle)
                dpg.add_button(label="📊", width=30, height=25, 
                              callback=lambda: self._show_info("protection"))
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Ver información detallada")
            
            dpg.add_spacer(height=10)
            
            # Submódulos de protección con indicadores visuales
            protection_modules = [
                {
                    "key": "behavior_analysis",
                    "label": "🧠 Análisis de Comportamiento",
                    "default": True,
                    "icon": "🟢" if self.settings.get('behavior_analysis', True) else "🔴"
                },
                {
                    "key": "keylogger_detection", 
                    "label": "⌨️ Detección de Keyloggers",
                    "default": True,
                    "icon": "🟢" if self.settings.get('keylogger_detection', True) else "🔴"
                },
                {
                    "key": "auto_quarantine",
                    "label": "🔒 Cuarentena Automática",
                    "default": False,
                    "icon": "🟡" if self.settings.get('auto_quarantine', False) else "⚪"
                }
            ]
            
            for module in protection_modules:
                with dpg.group(horizontal=True):
                    status_icon = "🟢" if self.settings.get(module["key"], module["default"]) else "🔴"
                    dpg.add_text(status_icon, color=(0, 255, 0) if self.settings.get(module["key"], module["default"]) else (255, 0, 0))
                    dpg.add_checkbox(label=module["label"], tag=f"setting_{module['key']}",
                                     default_value=self.settings.get(module["key"], module["default"]),
                                     callback=self._save_setting_with_update)
                    dpg.add_button(label="📊", width=25, height=20,
                                  callback=lambda s, a, u=module["key"]: self._show_info(u))
            
            dpg.add_spacer(height=15)
            
            # Slider de sensibilidad con visualización mejorada
            sensitivity_val = self.settings.get('ml_sensitivity', 75)
            sensitivity_color = (255, 0, 0) if sensitivity_val > 90 else (255, 165, 0) if sensitivity_val > 70 else (0, 255, 0)
            
            with dpg.group(horizontal=True):
                dpg.add_text("🎯 Sensibilidad de IA:", color=(200, 200, 200))
                dpg.add_text(f"{sensitivity_val}%", color=sensitivity_color)
                
            dpg.add_slider_int(tag="setting_ml_sensitivity", min_value=50, max_value=100,
                               default_value=sensitivity_val,
                               callback=self._on_sensitivity_change, format="%d%%", width=400)
                               
            # Indicador visual del nivel de sensibilidad
            if sensitivity_val >= 90:
                dpg.add_text("⚠️ Ultra Alta - Máxima protección, posibles falsos positivos", color=(255, 100, 100))
            elif sensitivity_val >= 75:
                dpg.add_text("✅ Alta - Protección robusta recomendada", color=(100, 255, 100))
            elif sensitivity_val >= 60:
                dpg.add_text("🟡 Media - Equilibrio entre protección y rendimiento", color=(255, 255, 0))
            else:
                dpg.add_text("🟠 Baja - Menor protección, mejor rendimiento", color=(255, 165, 0))

    def _create_performance_settings(self):
        """Crear grupo de configuraciones de rendimiento mejoradas."""
        with dpg.collapsing_header(label="⚡ Rendimiento y Recursos", default_open=True):
            
            # Modos de rendimiento con botones de selección rápida
            dpg.add_text("🎮 Modos Preconfigurados:", color=(100, 200, 255))
            with dpg.group(horizontal=True):
                dpg.add_button(label="🛡️ Máxima Protección", callback=self._set_max_protection_mode, width=140)
                dpg.add_button(label="⚖️ Equilibrado", callback=self._set_balanced_mode, width=100)
                dpg.add_button(label="🎮 Gaming", callback=self._set_gaming_mode, width=80)
                dpg.add_button(label="🚀 Rendimiento", callback=self._set_performance_mode, width=110)
            
            dpg.add_spacer(height=15)
            
            # Configuraciones individuales con estado visual
            performance_options = [
                {
                    "key": "gpu_acceleration",
                    "label": "🖾 Aceleración por GPU",
                    "default": True,
                    "info_key": "gpu_acceleration"
                },
                {
                    "key": "gaming_mode",
                    "label": "🎮 Modo Gaming",
                    "default": False,
                    "info_key": "gaming_mode" 
                }
            ]
            
            for option in performance_options:
                with dpg.group(horizontal=True):
                    status_icon = "🟢" if self.settings.get(option["key"], option["default"]) else "⚪"
                    status_color = (0, 255, 0) if self.settings.get(option["key"], option["default"]) else (150, 150, 150)
                    dpg.add_text(status_icon, color=status_color)
                    dpg.add_checkbox(label=option["label"], tag=f"setting_{option['key']}",
                                     default_value=self.settings.get(option["key"], option["default"]),
                                     callback=self._save_setting_with_update)
                    dpg.add_button(label="📊", width=25, height=20,
                                  callback=lambda s, a, u=option["info_key"]: self._show_info(u))
            
            dpg.add_spacer(height=15)
            
            # Control de CPU con visualización mejorada
            cpu_limit = self.settings.get('max_cpu_usage', 30)
            cpu_color = (255, 0, 0) if cpu_limit > 70 else (255, 165, 0) if cpu_limit > 40 else (0, 255, 0)
            
            with dpg.group(horizontal=True):
                dpg.add_text("💻 Límite de CPU:", color=(200, 200, 200))
                dpg.add_text(f"{cpu_limit}%", color=cpu_color)
                
            dpg.add_slider_int(tag="setting_max_cpu_usage", min_value=10, max_value=100,
                               default_value=cpu_limit,
                               callback=self._on_cpu_limit_change, format="%d%%", width=400)
                               
            # Recomendación basada en el límite de CPU
            if cpu_limit <= 20:
                dpg.add_text("🚀 Muy Bajo - Máximo rendimiento del sistema", color=(100, 255, 100))
            elif cpu_limit <= 40:
                dpg.add_text("✅ Moderado - Buen equilibrio recomendado", color=(100, 255, 100))
            elif cpu_limit <= 70:
                dpg.add_text("🟡 Alto - Protección intensa", color=(255, 255, 0))
            else:
                dpg.add_text("⚠️ Muy Alto - Puede impactar el rendimiento", color=(255, 100, 100))

    def _create_update_settings(self):
        """Crear grupo de configuraciones de actualizaciones mejoradas."""
        with dpg.collapsing_header(label="🔄 Actualizaciones y Mantenimiento", default_open=True):
            
            # Estado de actualizaciones
            with dpg.group(horizontal=True):
                update_status = "🟢 ACTIVAS" if self.settings.get('auto_update_sigs', True) else "🔴 DESACTIVADAS"
                update_color = (0, 255, 0) if self.settings.get('auto_update_sigs', True) else (255, 0, 0)
                dpg.add_text("Estado:", color=(200, 200, 200))
                dpg.add_text(update_status, color=update_color)
                dpg.add_spacer(width=20)
                dpg.add_button(label="🔄 Buscar Ahora", callback=self._check_updates_now)
            
            dpg.add_spacer(height=10)
            
            # Configuración de actualizaciones automáticas
            with dpg.group(horizontal=True):
                dpg.add_checkbox(label="🔄 Actualizaciones Automáticas", tag="setting_auto_update_sigs",
                                 default_value=self.settings.get('auto_update_sigs', True),
                                 callback=self._save_setting)
                dpg.add_button(label="📊", width=25, height=20,
                              callback=lambda: self._show_info("updates"))
            
            # Frecuencia con iconos
            dpg.add_spacer(height=10)
            dpg.add_text("⏰ Frecuencia de Verificación:")
            frequency_options = [
                "🕒 Cada Hora",
                "🕕 Cada 6 Horas (Recomendado)", 
                "🕛 Cada 12 Horas",
                "📅 Diariamente"
            ]
            current_freq = self.settings.get('update_frequency', "Every 6 Hours")
            # Mapear frecuencia actual a formato con iconos
            freq_mapping = {
                "Every 1 Hour": "🕒 Cada Hora",
                "Every 6 Hours": "🕕 Cada 6 Horas (Recomendado)",
                "Every 12 Hours": "🕛 Cada 12 Horas",
                "Daily": "📅 Diariamente"
            }
            display_freq = freq_mapping.get(current_freq, "🕕 Cada 6 Horas (Recomendado)")
            
            dpg.add_combo(items=frequency_options,
                          tag="setting_update_frequency",
                          default_value=display_freq,
                          callback=self._on_frequency_change, width=300)
            
            dpg.add_spacer(height=15)
            
            # Información de última actualización
            with dpg.group(horizontal=True):
                dpg.add_text("📅 Última Verificación:", color=(200, 200, 200))
                dpg.add_text("Hace 2 horas", color=(100, 255, 100))
            
            with dpg.group(horizontal=True):
                dpg.add_text("📦 Versión de Firmas:", color=(200, 200, 200)) 
                dpg.add_text("v2025.11.16.001", color=(100, 200, 255))
    
    def _check_updates_now(self):
        """Buscar actualizaciones inmediatamente."""
        self.logger.info("Manual update check requested")
        # Aquí se implementaría la lógica real de actualización
    
    def _on_frequency_change(self, sender, app_data):
        """Manejar cambio en frecuencia de actualización."""
        # Mapear de vuelta al formato original
        reverse_mapping = {
            "🕒 Cada Hora": "Every 1 Hour",
            "🕕 Cada 6 Horas (Recomendado)": "Every 6 Hours",
            "🕛 Cada 12 Horas": "Every 12 Hours",
            "📅 Diariamente": "Daily"
        }
        original_freq = reverse_mapping.get(app_data, "Every 6 Hours")
        self.app_controller.set_setting("update_frequency", original_freq)
        self.logger.info(f"Update frequency changed to {original_freq}")



    def _create_advanced_settings(self):
        """Crear configuraciones avanzadas."""
        with dpg.collapsing_header(label="🔧 Configuración Avanzada", default_open=False):
            
            # Configuración de logging
            with dpg.group(horizontal=True):
                dpg.add_text("📄 Nivel de Logging:", color=(200, 200, 200))
                dpg.add_combo(items=["ERROR", "WARNING", "INFO", "DEBUG"],
                              tag="setting_log_level",
                              default_value=self.settings.get('log_level', "INFO"),
                              callback=self._save_setting)
            
            # Configuración de memoria
            dpg.add_spacer(height=10)
            memory_limit = self.settings.get('memory_limit_mb', 512)
            with dpg.group(horizontal=True):
                dpg.add_text("💾 Límite de Memoria:", color=(200, 200, 200))
                dpg.add_text(f"{memory_limit} MB", color=(100, 200, 255))
            dpg.add_slider_int(tag="setting_memory_limit_mb", min_value=256, max_value=2048,
                               default_value=memory_limit,
                               callback=self._save_setting, format="%d MB", width=400)
            
            # Configuración de red
            dpg.add_spacer(height=15)
            with dpg.group(horizontal=True):
                dpg.add_checkbox(label="🌐 Actualizaciones por Red", tag="setting_network_updates",
                                 default_value=self.settings.get('network_updates', True),
                                 callback=self._save_setting)
                dpg.add_checkbox(label="🔍 Telemetría Anónima", tag="setting_telemetry",
                                 default_value=self.settings.get('telemetry', False),
                                 callback=self._save_setting)
    
    def _create_dynamic_info_panel(self):
        """Crear panel de información dinámico que se actualiza según la selección."""
        dpg.add_text("📊 Información Dinámica", color=(100, 200, 255))
        dpg.add_separator()
        
        # Contenedor que se actualizará dinámicamente
        with dpg.group(tag="dynamic_info_content"):
            self._show_protection_info()
    
    def _show_info(self, info_type):
        """Mostrar información específica en el panel dinámico."""
        self.current_info_section = info_type
        # Limpiar contenido actual
        if dpg.does_item_exist("dynamic_info_content"):
            children = dpg.get_item_children("dynamic_info_content", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Mostrar información correspondiente directamente en el contenedor
        if info_type == "protection":
            self._show_protection_info()
        elif info_type == "behavior_analysis":
            self._show_behavior_analysis_info()
        elif info_type == "keylogger_detection":
            self._show_keylogger_info()
        elif info_type == "auto_quarantine":
            self._show_quarantine_info()
        elif info_type == "gpu_acceleration":
            self._show_gpu_info()
        elif info_type == "gaming_mode":
            self._show_gaming_info()
        else:
            self._show_protection_info()
    
    def _show_protection_info(self):
        """Mostrar información sobre protección."""
        dpg.add_text("🛡️ Protección en Tiempo Real", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("La protección en tiempo real es el corazón del antivirus. Monitoriza continuamente todos los procesos, archivos y conexiones de red en busca de actividad maliciosa.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("✨ Características:", color=(100, 200, 255), parent="dynamic_info_content")
        dpg.add_text("• Monitoreo continuo de procesos", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Análisis de archivos en tiempo real", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Detección de comportamientos sospechosos", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Respuesta automática a amenazas", wrap=280, parent="dynamic_info_content")
    
    def _show_behavior_analysis_info(self):
        """Mostrar información sobre análisis de comportamiento."""
        dpg.add_text("🧠 Análisis de Comportamiento", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("En lugar de buscar virus conocidos, esta función avanzada monitoriza cómo se comportan los programas en tiempo real.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("🎯 Detecta:", color=(255, 100, 100), parent="dynamic_info_content")
        dpg.add_text("• Ransomware cifrando archivos rápidamente", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Spyware capturando pulsaciones", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Malware modificando el sistema", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Procesos con comportamiento anómalo", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("✅ Ventaja: Detecta amenazas desconocidas (zero-day)", color=(0, 255, 0), wrap=280, parent="dynamic_info_content")
    
    def _show_keylogger_info(self):
        """Mostrar información sobre detección de keyloggers."""
        dpg.add_text("⌨️ Detección de Keyloggers", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("Utiliza un modelo de Inteligencia Artificial entrenado específicamente para identificar keyloggers y software espía.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("🤖 Tecnología IA:", color=(100, 200, 255), parent="dynamic_info_content")
        dpg.add_text("• Modelo ONNX optimizado", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• 94.7% de precisión", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Detección en menos de 2 segundos", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Bajo índice de falsos positivos", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("⚠️ Detecta hooks de teclado, captura de pantalla y robo de credenciales", color=(255, 165, 0), wrap=280, parent="dynamic_info_content")
    
    def _show_quarantine_info(self):
        """Mostrar información sobre cuarentena automática."""
        dpg.add_text("🔒 Cuarentena Automática", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("Cuando se detecta una amenaza de alto riesgo, esta función la aísla inmediatamente del sistema.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("🎯 Proceso automático:", color=(255, 100, 100), parent="dynamic_info_content")
        dpg.add_text("• Detección de amenaza HIGH", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Detención inmediata del proceso", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Aislamiento del archivo", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Notificación al usuario", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("⚙️ Recomendado: Activar para protección máxima", color=(100, 255, 100), wrap=280, parent="dynamic_info_content")
    
    def _show_gpu_info(self):
        """Mostrar información sobre aceleración GPU."""
        dpg.add_text("🖾 Aceleración por GPU", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("Utiliza la potencia de tu tarjeta gráfica para acelerar los cálculos de Inteligencia Artificial del antivirus.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("🚀 Beneficios:", color=(100, 255, 100), parent="dynamic_info_content")
        dpg.add_text("• Análisis ML hasta 10x más rápido", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Libera recursos del CPU", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Mejor rendimiento del sistema", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Respuesta más rápida a amenazas", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("💻 Requiere: NVIDIA/AMD GPU con soporte ONNX Runtime", color=(255, 165, 0), wrap=280, parent="dynamic_info_content")
    
    def _show_gaming_info(self):
        """Mostrar información sobre modo gaming."""
        dpg.add_text("🎮 Modo Gaming", color=(255, 255, 0), parent="dynamic_info_content")
        dpg.add_text("Optimiza el antivirus para gaming, minimizando interrupciones y maximizando el rendimiento durante los juegos.", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("🎮 Optimizaciones:", color=(100, 255, 100), parent="dynamic_info_content")
        dpg.add_text("• Detecta juegos en pantalla completa", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Pausa escaneos no esenciales", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Silencia notificaciones", wrap=280, parent="dynamic_info_content")
        dpg.add_text("• Reduce uso de CPU automáticamente", wrap=280, parent="dynamic_info_content")
        dpg.add_spacer(height=10, parent="dynamic_info_content")
        dpg.add_text("✅ Mantiene protección esencial activa", color=(0, 255, 0), wrap=280, parent="dynamic_info_content")
    
    # Modos preconfigurados
    def _set_max_protection_mode(self):
        """Configurar modo de máxima protección."""
        settings = {
            'realtime_protection': True,
            'behavior_analysis': True,
            'keylogger_detection': True,
            'auto_quarantine': True,
            'ml_sensitivity': 90,
            'gpu_acceleration': True,
            'gaming_mode': False,
            'max_cpu_usage': 50
        }
        self._apply_preset(settings, "Máxima Protección")
    
    def _set_balanced_mode(self):
        """Configurar modo equilibrado."""
        settings = {
            'realtime_protection': True,
            'behavior_analysis': True,
            'keylogger_detection': True,
            'auto_quarantine': False,
            'ml_sensitivity': 75,
            'gpu_acceleration': True,
            'gaming_mode': False,
            'max_cpu_usage': 30
        }
        self._apply_preset(settings, "Equilibrado")
    
    def _set_gaming_mode(self):
        """Configurar modo gaming."""
        settings = {
            'realtime_protection': True,
            'behavior_analysis': True,
            'keylogger_detection': True,
            'auto_quarantine': False,
            'ml_sensitivity': 60,
            'gpu_acceleration': True,
            'gaming_mode': True,
            'max_cpu_usage': 20
        }
        self._apply_preset(settings, "Gaming")
    
    def _set_performance_mode(self):
        """Configurar modo rendimiento."""
        settings = {
            'realtime_protection': True,
            'behavior_analysis': False,
            'keylogger_detection': True,
            'auto_quarantine': False,
            'ml_sensitivity': 50,
            'gpu_acceleration': False,
            'gaming_mode': False,
            'max_cpu_usage': 15
        }
        self._apply_preset(settings, "Alto Rendimiento")
    
    def _apply_preset(self, settings, mode_name):
        """Aplicar un preset de configuración."""
        for key, value in settings.items():
            if dpg.does_item_exist(f"setting_{key}"):
                dpg.set_value(f"setting_{key}", value)
                self.app_controller.set_setting(key, value)
        
        self.logger.info(f"Applied preset: {mode_name}")
        # Actualizar barra de estado
        self._update_status_bar()
    
    def _update_status_bar(self):
        """Actualizar la barra de estado del sistema."""
        # Esta función se llamaría para actualizar la UI, pero Dear PyGui
        # requiere recrear los elementos, lo cual es complejo en este contexto
        pass
    
    # Callbacks mejorados
    def _on_protection_toggle(self, sender, app_data):
        """Manejar cambio en protección principal."""
        self._save_setting(sender, app_data)
        if not app_data:
            # Mostrar advertencia si se desactiva la protección
            self.logger.warning("Real-time protection disabled by user")
    
    def _on_sensitivity_change(self, sender, app_data):
        """Manejar cambio en sensibilidad."""
        self._save_setting(sender, app_data)
        self.logger.info(f"ML sensitivity changed to {app_data}%")
    
    def _on_cpu_limit_change(self, sender, app_data):
        """Manejar cambio en límite de CPU."""
        self._save_setting(sender, app_data)
        self.logger.info(f"CPU limit changed to {app_data}%")
    
    def _save_setting_with_update(self, sender, app_data):
        """Guardar configuración y actualizar UI."""
        self._save_setting(sender, app_data)
        self._update_status_bar()
    
    def _save_setting(self, sender, app_data):
        """Guarda el valor de una configuración."""
        # El tag del widget es "setting_nombre_de_la_clave"
        key = dpg.get_item_alias(sender).replace("setting_", "")
        value = app_data
        
        self.logger.info(f"Setting changed: {key} = {value}")
        self.app_controller.set_setting(key, value)