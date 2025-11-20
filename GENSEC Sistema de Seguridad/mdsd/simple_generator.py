#!/usr/bin/env python3
"""
MDSD Simple Generator - Como "Copiar Código" pero Inteligente
===========================================================

Genera detectores automáticamente desde configuración YAML
"""

import os
import yaml
import re
from pathlib import Path


class SimpleDetectorGenerator:
    """Generador simple de detectores - MDSD básico"""

    def __init__(self):
        self.template_dir = Path("mdsd/templates")
        self.output_dir = Path("plugins/detectors/generated")

    def generate_detector(self, config_file: str):
        """
        Genera detector desde configuración YAML

        Es como copiar código, pero las variables se llenan automáticamente
        """
        print(f"Generando detector desde: {config_file}")

        # 1. Leer configuración
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        # 2. Leer template
        template_path = self.template_dir / "detector_template.py"
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()

        # 3. Generar código (reemplazar variables)
        generated_code = self._fill_template(template, config)

        # 4. Guardar archivo
        detector_name = config["name"].lower().replace(" ", "_")
        output_file = self.output_dir / f"{detector_name}_detector.py"

        # Crear directorio si no existe
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(generated_code)

        print(f"Detector generado: {output_file}")
        print(f"Lineas de codigo: {len(generated_code.splitlines())}")

        return output_file

    def _fill_template(self, template_file_content: str, config: dict) -> str:
        """
        Llena el template con datos de configuración

        Como buscar y reemplazar, pero automático:
        {detector_name} → "USB Malware Detector"
        {threshold} → 0.7
        """

        # Variables básicas
        detector_name = config["name"]
        detector_class_name = self._to_class_name(detector_name)
        description = config.get("description", f"Detector para {detector_name}")

        # Generar componentes
        trigger_checks = self._generate_trigger_checks(config.get("triggers", []))
        trigger_logic = self._generate_trigger_logic(config.get("triggers", []))
        response_actions = self._generate_responses(config.get("responses", []))
        helper_methods = self._generate_helper_methods(config.get("triggers", []))

        # Extraer el template del archivo
        template_start = template_file_content.find("DETECTOR_TEMPLATE = '''") + len(
            "DETECTOR_TEMPLATE = '''"
        )
        template_end = template_file_content.rfind("'''")
        template = template_file_content[template_start:template_end].strip()

        # Usar format() para reemplazar placeholders
        try:
            result = template.format(
                detector_name=detector_name,
                class_name=detector_class_name,
                description=description,
                priority=config.get("priority", 80),
                threshold=config.get("threshold", 0.7),
                trigger_checks=trigger_checks,
                trigger_logic=trigger_logic,
                response_actions=response_actions,
                helper_methods=helper_methods,
            )
            return result
        except KeyError as e:
            print(f"❌ Error en template: falta placeholder {e}")
            return template

    def _to_class_name(self, name: str) -> str:
        """Convierte 'USB Malware' → 'UsbMalware'"""
        words = re.findall(r"\w+", name)
        return "".join(word.capitalize() for word in words)

    def _generate_trigger_checks(self, triggers: list) -> str:
        """Genera documentación de triggers"""
        if not triggers:
            return "        - Sin triggers configurados"

        lines = []
        for i, trigger in enumerate(triggers):
            condition = trigger.get("condition", "unknown")
            value = trigger.get("value", "N/A")
            lines.append(f"        - Trigger {i+1}: {condition} = {value}")

        return "\n".join(lines)

    def _generate_trigger_logic(self, triggers: list) -> str:
        """Genera código de evaluación de triggers"""
        if not triggers:
            return "            # Sin triggers - siempre threat_score = 0"

        lines = []
        for i, trigger in enumerate(triggers):
            condition = trigger.get("condition", "")
            value = trigger.get("value", "")
            weight = trigger.get("weight", 1.0)

            lines.append(f"            # Trigger {i+1}: {condition}")

            if "api_call" in condition.lower():
                lines.append(
                    f"            api_calls = process_data.get('api_calls', [])"
                )
                lines.append(f"            if '{value}' in api_calls:")
                lines.append(f"                threat_score += {weight}")

            elif "cpu" in condition.lower():
                lines.append(
                    f"            cpu_usage = process_data.get('cpu_usage', 0)"
                )
                lines.append(f"            if cpu_usage > {value}:")
                lines.append(f"                threat_score += {weight}")

            elif "network" in condition.lower():
                lines.append(
                    f"            connections = process_data.get('network_connections', [])"
                )
                lines.append(
                    f"            suspicious_count = len([c for c in connections if 'suspicious' in str(c)])"
                )
                lines.append(f"            if suspicious_count > 0:")
                lines.append(f"                threat_score += {weight}")
            else:
                lines.append(f"            # Trigger genérico: {condition} = {value}")
                lines.append(
                    f"            if process_data.get('{condition}', 0) > {value}:"
                )
                lines.append(f"                threat_score += {weight}")

            lines.append("")

        return "\n".join(lines)

    def _generate_responses(self, responses: list) -> str:
        """Genera código de respuestas"""
        if not responses:
            return "                pass  # Sin respuestas configuradas"

        lines = []
        for response in responses:
            action = response.get("action", "")
            level = response.get("level", "info")

            if action == "log":
                lines.append(
                    f"                self.logger.{level}(f'🔍 {{self.name}}: Amenaza detectada')"
                )
            elif action == "alert":
                lines.append(
                    f'                self.logger.warning(f\'🚨 ALERT [{level}]: {{process_data.get("name", "unknown")}}\')'
                )
            elif action == "quarantine":
                lines.append(
                    f'                self.logger.critical(f\'🔒 QUARANTINE [{level}]: {{process_data.get("name", "unknown")}}\')'
                )
            else:
                lines.append(f"                # Respuesta: {action} - {level}")

        return "\n".join(lines)

    def _generate_helper_methods(self, triggers: list) -> str:
        """Genera métodos auxiliares si son necesarios"""
        if not triggers:
            return ""

        methods = []

        # Si hay triggers de red, agregar método helper
        if any("network" in str(t).lower() for t in triggers):
            methods.append(
                """
    def _check_network_activity(self, connections: list) -> bool:
        \"\"\"Helper para análisis de red\"\"\"
        suspicious_ports = [4444, 5555, 6666, 8080]
        return any(conn.get('port', 0) in suspicious_ports for conn in connections)"""
            )

        return "\n".join(methods)


def main():
    """Demo del generador simple"""
    generator = SimpleDetectorGenerator()

    # Ejemplo de uso (sin emojis para compatibilidad Windows)
    print("MDSD Simple Generator - Demo")
    print("=" * 50)

    # Buscar archivos de configuración
    config_files = list(Path("mdsd/configs").glob("*.yaml"))

    if not config_files:
        print("No se encontraron archivos de configuracion en mdsd/configs/")
        print("Crea un archivo .yaml en esa carpeta para generar detectores")
        return

    for config_file in config_files:
        try:
            output_file = generator.generate_detector(config_file)
            print(f"Generado: {output_file}")
        except Exception as e:
            print(f"Error generando {config_file}: {e}")


if __name__ == "__main__":
    main()
