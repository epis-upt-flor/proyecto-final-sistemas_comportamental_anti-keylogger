"""
Validador de Configuración Segura
================================

Evita que usuarios sin experiencia configuren el sistema de forma peligrosa.
Proporciona advertencias y sugerencias para mantener la seguridad.
"""

import json
from typing import Dict, List, Tuple, Any
from pathlib import Path


class ConfigurationValidator:
    """Valida configuraciones de usuario para evitar configuraciones inseguras"""

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.safe_profiles = self._load_safe_profiles()

    def _load_safe_profiles(self) -> Dict[str, Any]:
        """Carga perfiles seguros y reglas de validación"""
        try:
            profiles_file = self.config_dir / "safe_profiles.json"
            if profiles_file.exists():
                with open(profiles_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error cargando perfiles seguros: {e}")

        # Configuración por defecto si no existe el archivo
        return {
            "validation_rules": {
                "cpu_threshold": {"min": 50, "max": 95, "default": 75},
                "memory_threshold_mb": {"min": 100, "max": 500, "default": 200},
                "ml_confidence": {"min": 0.3, "max": 0.95, "default": 0.7},
                "scan_interval": {"min": 1, "max": 10, "default": 3},
            }
        }

    def validate_configuration(
        self, config: Dict[str, Any]
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Valida una configuración y retorna:
        - bool: Si la configuración es segura
        - List[str]: Lista de errores críticos
        - List[str]: Lista de advertencias
        """
        errors = []
        warnings = []

        # Validar detectores
        detector_errors, detector_warnings = self._validate_detectors(
            config.get("detectors", {})
        )
        errors.extend(detector_errors)
        warnings.extend(detector_warnings)

        # Validar alertas
        alert_errors, alert_warnings = self._validate_alerts(config.get("alerts", {}))
        errors.extend(alert_errors)
        warnings.extend(alert_warnings)

        # Validar rendimiento
        perf_errors, perf_warnings = self._validate_performance(config)
        errors.extend(perf_errors)
        warnings.extend(perf_warnings)

        is_safe = len(errors) == 0
        return is_safe, errors, warnings

    def _validate_detectors(
        self, detectors: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        """Valida configuración de detectores"""
        errors = []
        warnings = []

        # Verificar que al menos un detector esté habilitado
        enabled_detectors = []
        for detector_name, detector_config in detectors.items():
            if detector_config.get("enabled", False):
                enabled_detectors.append(detector_name)

        if not enabled_detectors:
            errors.append(
                "🚨 CRÍTICO: Todos los detectores están deshabilitados. Tu sistema no tendrá protección."
            )

        # Validar configuración de behavior_detector
        if "behavior_detector" in detectors:
            behavior_config = detectors["behavior_detector"].get("config", {})

            # CPU threshold
            cpu_threshold = behavior_config.get("cpu_threshold", 75)
            rules = self.safe_profiles.get("validation_rules", {}).get(
                "cpu_threshold", {}
            )

            if cpu_threshold < rules.get("min", 50):
                errors.append(
                    f"❌ Umbral de CPU muy bajo ({cpu_threshold}%). Mínimo recomendado: {rules.get('min', 50)}%"
                )
            elif cpu_threshold < 60:
                warnings.append(
                    f"⚠️ Umbral de CPU bajo ({cpu_threshold}%). Puede generar muchas falsas alarmas."
                )
            elif cpu_threshold > 90:
                warnings.append(
                    f"⚠️ Umbral de CPU alto ({cpu_threshold}%). Puede pasar amenazas por alto."
                )

            # Memory threshold
            memory_threshold = behavior_config.get("memory_threshold_mb", 200)
            mem_rules = self.safe_profiles.get("validation_rules", {}).get(
                "memory_threshold_mb", {}
            )

            if memory_threshold < mem_rules.get("min", 100):
                errors.append(
                    f"❌ Umbral de memoria muy bajo ({memory_threshold}MB). Mínimo: {mem_rules.get('min', 100)}MB"
                )
            elif memory_threshold < 150:
                warnings.append(
                    f"⚠️ Umbral de memoria bajo. Puede generar falsas alarmas."
                )

        # Validar ML detector
        if "ml_detector" in detectors:
            ml_config = detectors["ml_detector"].get("config", {})
            confidence = ml_config.get("confidence_threshold", 0.7)

            if confidence < 0.3:
                errors.append(
                    "❌ Confianza de IA muy baja. Tendrás muchas falsas alarmas."
                )
            elif confidence < 0.5:
                warnings.append("⚠️ Confianza de IA baja. Considera subirla a 60-80%.")
            elif confidence > 0.95:
                warnings.append(
                    "⚠️ Confianza de IA muy alta. Puede pasar amenazas por alto."
                )

        return errors, warnings

    def _validate_alerts(self, alerts: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Valida configuración de alertas"""
        errors = []
        warnings = []

        # Verificar que al menos un método de alerta esté habilitado
        alert_methods = [
            alerts.get("desktop_notifications", False),
            alerts.get("sound_alerts", False),
            alerts.get("email_alerts", False),
        ]

        if not any(alert_methods):
            errors.append(
                "🚨 CRÍTICO: No hay métodos de alerta habilitados. No te enterarás de amenazas detectadas."
            )

        # Verificar nivel de severidad
        min_severity = alerts.get("min_severity", "medium")
        if min_severity == "critical":
            warnings.append(
                "⚠️ Solo alertas críticas habilitadas. Puede pasar amenazas importantes por alto."
            )

        return errors, warnings

    def _validate_performance(
        self, config: Dict[str, Any]
    ) -> Tuple[List[str], List[str]]:
        """Valida configuración de rendimiento"""
        errors = []
        warnings = []

        # Validar intervalo de escaneo
        detectors = config.get("detectors", {})
        behavior_config = detectors.get("behavior_detector", {}).get("config", {})
        scan_interval = behavior_config.get("scan_interval", 3)

        if scan_interval > 10:
            warnings.append(
                f"⚠️ Intervalo de escaneo muy largo ({scan_interval}s). Considera reducirlo para mejor protección."
            )
        elif scan_interval < 1:
            errors.append("❌ Intervalo de escaneo demasiado corto. Mínimo: 1 segundo.")

        return errors, warnings

    def get_safe_profile(self, profile_name: str) -> Dict[str, Any]:
        """Obtiene una configuración de perfil seguro"""
        profiles = self.safe_profiles.get("profile_configurations", {})
        if profile_name in profiles:
            return profiles[profile_name]["settings"]

        # Retornar perfil por defecto si no existe
        return profiles.get("home", {}).get("settings", {})

    def suggest_fixes(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Sugiere correcciones para una configuración problemática"""
        is_safe, errors, warnings = self.validate_configuration(config)

        if is_safe:
            return config

        # Aplicar correcciones automáticas
        fixed_config = config.copy()

        # Asegurar que al menos behavior_detector esté habilitado
        if not any(
            d.get("enabled", False) for d in fixed_config.get("detectors", {}).values()
        ):
            if "detectors" not in fixed_config:
                fixed_config["detectors"] = {}
            if "behavior_detector" not in fixed_config["detectors"]:
                fixed_config["detectors"]["behavior_detector"] = {}
            fixed_config["detectors"]["behavior_detector"]["enabled"] = True

        # Asegurar que las alertas de escritorio estén habilitadas
        if not any(
            [
                fixed_config.get("alerts", {}).get("desktop_notifications", False),
                fixed_config.get("alerts", {}).get("sound_alerts", False),
                fixed_config.get("alerts", {}).get("email_alerts", False),
            ]
        ):
            if "alerts" not in fixed_config:
                fixed_config["alerts"] = {}
            fixed_config["alerts"]["desktop_notifications"] = True

        # Aplicar valores seguros para thresholds
        detectors = fixed_config.get("detectors", {})
        if "behavior_detector" in detectors:
            behavior_config = detectors["behavior_detector"].setdefault("config", {})

            # CPU threshold
            cpu_threshold = behavior_config.get("cpu_threshold", 75)
            if cpu_threshold < 50 or cpu_threshold > 95:
                behavior_config["cpu_threshold"] = 75

            # Memory threshold
            memory_threshold = behavior_config.get("memory_threshold_mb", 200)
            if memory_threshold < 100 or memory_threshold > 500:
                behavior_config["memory_threshold_mb"] = 200

        return fixed_config

    def get_user_friendly_explanation(self, config: Dict[str, Any]) -> str:
        """Genera explicación amigable de la configuración"""
        explanations = []

        detectors = config.get("detectors", {})
        enabled_detectors = [
            name for name, cfg in detectors.items() if cfg.get("enabled", False)
        ]

        if enabled_detectors:
            explanations.append(
                f"🛡️ Protecciones activas: {', '.join(enabled_detectors)}"
            )
        else:
            explanations.append("⚠️ Sin protecciones activas")

        alerts = config.get("alerts", {})
        alert_methods = []
        if alerts.get("desktop_notifications"):
            alert_methods.append("ventanas")
        if alerts.get("sound_alerts"):
            alert_methods.append("sonidos")
        if alerts.get("email_alerts"):
            alert_methods.append("email")

        if alert_methods:
            explanations.append(f"🔔 Alertas por: {', '.join(alert_methods)}")

        severity = alerts.get("min_severity", "medium")
        severity_names = {
            "low": "todas",
            "medium": "importantes",
            "high": "serias",
            "critical": "críticas",
        }
        explanations.append(
            f"📊 Mostrando alertas: {severity_names.get(severity, 'desconocido')}"
        )

        return "\n".join(explanations)


# Función utilitaria para usar desde la UI
def validate_ui_config(config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Función simple para validar configuración desde la UI
    Retorna: (es_segura, mensaje_para_usuario)
    """
    validator = ConfigurationValidator()
    is_safe, errors, warnings = validator.validate_configuration(config)

    if is_safe and not warnings:
        return True, "✅ Configuración segura y óptima"

    messages = []
    if errors:
        messages.append("🚨 PROBLEMAS CRÍTICOS:")
        messages.extend(errors)
        messages.append("")

    if warnings:
        messages.append("⚠️ ADVERTENCIAS:")
        messages.extend(warnings)

    if errors:
        messages.append(
            "❌ Por favor corrige los problemas críticos antes de continuar."
        )
    else:
        messages.append(
            "✅ La configuración es funcional, pero considera las advertencias."
        )

    return len(errors) == 0, "\n".join(messages)
