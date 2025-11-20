"""
TDD #3: Safe Process Validation for False Positive Prevention
============================================================

Test-Driven Development para validación de procesos seguros.
Crítico para UX - evita que el antivirus genere falsas alarmas
con software legítimo como navegadores, editores de texto, etc.

Este test asegura que el antivirus sea inteligente y no moleste
al usuario con alertas innecesarias de programas conocidos.
"""

import sys
from pathlib import Path

# Agregar el directorio raíz al path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import pytest
from datetime import datetime

# 🔧 TDD #3 REFACTOR: Importar ProcessMonitorPlugin REAL del antivirus
from plugins.monitors.process_monitor.plugin import ProcessMonitorPlugin


class ProcessValidator:
    """
    Placeholder class para implementar con TDD.
    Esta clase se desarrollará completamente siguiendo el ciclo Red-Green-Refactor.
    """

    def __init__(self, config=None):
        self.config = config or {}

    def is_process_safe(self, process_data):
        """
        IMPLEMENTACIÓN TDD - FASE REFACTOR: Algoritmo completo para validación de procesos.

        Args:
            process_data: Diccionario con información del proceso:
                - name: Nombre del proceso
                - path: Ruta completa del ejecutable
                - digital_signature: Firma digital (opcional)

        Returns:
            Diccionario con resultado de la validación completa
        """
        import re

        # Inicializar resultado
        result = {
            "is_safe": None,  # None = requiere investigación
            "confidence": 0.5,  # Neutral por defecto
            "threat_score": 0.5,  # Neutral por defecto
            "category": "unknown",
            "threat_indicators": [],
            "trust_factors": [],
            "requires_investigation": True,  # Por defecto requiere investigación
            "recommendation": "monitor",
        }

        process_name = process_data.get("name", "").lower()
        process_path = process_data.get("path", "").lower()
        digital_signature = process_data.get("digital_signature")
        signature_valid = process_data.get("signature_valid", False)

        # Obtener configuración
        safe_processes = self.config.get("safe_processes", {})
        suspicious_processes = self.config.get("suspicious_processes", {})
        trusted_locations = [
            loc.lower() for loc in self.config.get("trusted_locations", [])
        ]

        # Variables para scoring
        confidence_score = 0.5
        threat_score = 0.5
        trust_factors = []
        threat_indicators = []
        category = "unknown"

        # ANÁLISIS 1: Procesos conocidos seguros
        all_safe = []
        category_mapping = {
            "system_processes": "system_process",
            "browsers": "browser",
            "productivity": "productivity",
            "gaming": "gaming",
        }

        for cat_name, processes in safe_processes.items():
            for proc in processes:
                all_safe.append(proc.lower())
                if process_name == proc.lower():
                    category = category_mapping.get(cat_name, cat_name)
                    confidence_score += 0.4
                    threat_score -= 0.4
                    trust_factors.append("known_safe_process")
                    break

        # ANÁLISIS 2: Procesos obviamente maliciosos
        malware_names = suspicious_processes.get("obvious_malware", [])
        for malware in malware_names:
            if process_name == malware.lower():
                category = "malware"
                confidence_score = 0.05
                threat_score = 0.95
                threat_indicators.append("obvious_malware")
                break

        # ANÁLISIS 3: Patrones sospechosos en nombres
        suspicious_patterns = suspicious_processes.get("suspicious_patterns", [])
        for pattern in suspicious_patterns:
            if re.match(pattern, process_name):
                threat_indicators.append("suspicious_naming_pattern")
                confidence_score -= 0.2
                threat_score += 0.2
                break

        # ANÁLISIS 4: Ubicación del proceso
        is_in_trusted_location = any(
            process_path.startswith(loc) for loc in trusted_locations
        )

        if is_in_trusted_location:
            trust_factors.append("trusted_location")
            confidence_score += 0.2
            threat_score -= 0.2
        else:
            # Proceso legítimo en ubicación sospechosa
            if process_name in all_safe:
                threat_indicators.append("suspicious_location")
                threat_indicators.append("impersonation_attempt")
                confidence_score -= 0.3
                threat_score += 0.3

        # ANÁLISIS 5: Firma digital
        trusted_publishers = [
            "microsoft corporation",
            "google llc",
            "adobe systems incorporated",
            "mozilla corporation",
            "apple inc.",
            "nvidia corporation",
        ]

        if digital_signature and signature_valid:
            trust_factors.append("trusted_signature")
            signature_lower = digital_signature.lower()

            if any(publisher in signature_lower for publisher in trusted_publishers):
                trust_factors.append("reputable_publisher")
                confidence_score += 0.3
                threat_score -= 0.3
            else:
                confidence_score += 0.1
                threat_score -= 0.1
        elif digital_signature is None or not signature_valid:
            # Sin firma o firma inválida
            confidence_score -= 0.1
            threat_score += 0.1

        # Normalizar scores con redondeo para evitar problemas de float
        confidence_score = round(max(0.0, min(1.0, confidence_score)), 10)
        threat_score = round(max(0.0, min(1.0, threat_score)), 10)

        # DECISIÓN FINAL
        result["confidence"] = confidence_score
        result["threat_score"] = threat_score
        result["category"] = category
        result["trust_factors"] = trust_factors
        result["threat_indicators"] = threat_indicators

        # Umbrales de decisión
        threshold = self.config.get("reputation_threshold", 0.8)

        if "obvious_malware" in threat_indicators:
            # Malware obvio - bloquear inmediatamente
            result["is_safe"] = False
            result["requires_investigation"] = False
            result["recommendation"] = "block"
        elif confidence_score >= 0.7 and threat_score <= 0.2:
            # Proceso altamente confiable (umbral más bajo para procesos conocidos)
            result["is_safe"] = True
            result["requires_investigation"] = False
            result["recommendation"] = "allow"
        elif confidence_score <= 0.3 or threat_score >= 0.7:
            # Proceso peligroso
            result["is_safe"] = False
            result["requires_investigation"] = True
            result["recommendation"] = "quarantine"
        elif (
            "suspicious_location" in threat_indicators
            and "impersonation_attempt" in threat_indicators
        ):
            # Posible suplantación
            result["is_safe"] = False
            result["requires_investigation"] = True
            result["recommendation"] = "quarantine"
        else:
            # Proceso desconocido - requiere análisis
            result["is_safe"] = None
            result["requires_investigation"] = True
            result["recommendation"] = "monitor"

        return result

    def get_process_reputation(self, process_data):
        """
        Método auxiliar a implementar con TDD.
        """
        raise NotImplementedError("Método a implementar con TDD")


class TestSafeProcessValidationTDD:
    """
    Suite de tests TDD para validación de procesos seguros.

    Implementa sistema de whitelist/blacklist para evitar
    falsos positivos con software legítimo popular.
    """

    @pytest.fixture
    def process_validator(self):
        """Instancia del validador de procesos para tests"""
        config = {
            "safe_processes": {
                # Procesos del sistema Windows
                "system_processes": [
                    "notepad.exe",
                    "calc.exe",
                    "mspaint.exe",
                    "explorer.exe",
                    "dwm.exe",
                    "winlogon.exe",
                    "csrss.exe",
                    "smss.exe",
                ],
                # Navegadores populares
                "browsers": [
                    "chrome.exe",
                    "firefox.exe",
                    "msedge.exe",
                    "opera.exe",
                    "brave.exe",
                    "safari.exe",
                    "iexplore.exe",
                ],
                # Office y productividad
                "productivity": [
                    "winword.exe",
                    "excel.exe",
                    "powerpnt.exe",
                    "outlook.exe",
                    "notepad++.exe",
                    "code.exe",
                    "devenv.exe",
                ],
                # Gaming y entretenimiento
                "gaming": [
                    "steam.exe",
                    "discord.exe",
                    "spotify.exe",
                    "vlc.exe",
                    "obs64.exe",
                    "epicgameslauncher.exe",
                ],
            },
            "suspicious_processes": {
                # Nombres obviamente maliciosos
                "obvious_malware": [
                    "keylogger.exe",
                    "stealer.exe",
                    "backdoor.exe",
                    "rootkit.exe",
                    "trojan.exe",
                    "virus.exe",
                ],
                # Patrones sospechosos
                "suspicious_patterns": [
                    r"^[a-f0-9]{8,}\.exe$",  # Nombres hexadecimales
                    r"^[0-9]+\.exe$",  # Solo números
                    r"^.{1,3}\.exe$",  # Muy cortos
                    r".*temp.*\.exe$",  # En carpeta temp
                ],
            },
            "trusted_locations": [
                "C:\\Windows\\System32\\",
                "C:\\Windows\\",
                "C:\\Program Files\\",
                "C:\\Program Files (x86)\\",
            ],
            "reputation_threshold": 0.8,
        }
        # ✅ Usar ProcessMonitorPlugin REAL del antivirus
        plugin = ProcessMonitorPlugin("process_validator_test", "1.0")
        plugin.config = config  # Configurar directamente

        # Configurar logger mínimo para tests
        import logging

        plugin.logger = logging.getLogger("test_process_validator")
        plugin.logger.setLevel(logging.DEBUG)

        return plugin

    # ========================
    # FASE RED: Tests que deben fallar inicialmente
    # ========================

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_notepad_should_be_validated_as_safe(self, process_validator):
        """
        TEST RED #1: Notepad.exe debe ser validado como seguro.

        Notepad es el editor de texto estándar de Windows.
        Es imposible que sea malware - debe tener confianza máxima.

        Este test DEBE FALLAR porque is_process_safe() no existe.
        """
        # Arrange - Proceso notepad estándar
        process_data = {
            "name": "notepad.exe",
            "path": "C:\\Windows\\System32\\notepad.exe",
            "pid": 1234,
            "cpu_percent": 0.1,
            "memory_mb": 15.2,
            "digital_signature": "Microsoft Corporation",
            "started_at": datetime.now().isoformat(),
        }

        # Act - Esta función debe implementarse con TDD
        result = process_validator.is_process_safe(process_data)

        # Assert - Debe ser completamente seguro
        assert result["is_safe"] is True, "Notepad debe ser validado como seguro"
        assert (
            result["confidence"] >= 0.9
        ), f"Confianza alta esperada (>=0.9), got {result['confidence']}"
        assert (
            result["threat_score"] == 0.0
        ), f"Sin amenaza esperado (0.0), got {result['threat_score']}"
        assert (
            result["category"] == "system_process"
        ), "Debe ser categorizado como proceso del sistema"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_chrome_browser_should_be_validated_as_safe(self, process_validator):
        """
        TEST RED #2: Google Chrome debe ser validado como seguro.

        Chrome es el navegador más popular del mundo.
        Millones de usuarios lo usan diariamente - debe ser seguro.
        """
        # Arrange - Proceso Chrome legítimo
        process_data = {
            "name": "chrome.exe",
            "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "pid": 5678,
            "cpu_percent": 12.5,
            "memory_mb": 250.8,
            "digital_signature": "Google LLC",
            "command_line": "chrome.exe --no-sandbox",
            "started_at": datetime.now().isoformat(),
        }

        # Act
        result = process_validator.is_process_safe(process_data)

        # Assert - Navegador popular debe ser seguro
        assert result["is_safe"] is True, "Chrome debe ser validado como seguro"
        assert (
            result["confidence"] >= 0.85
        ), f"Confianza alta para Chrome, got {result['confidence']}"
        assert result["threat_score"] == 0.0, "Chrome no debe tener score de amenaza"
        assert result["category"] == "browser", "Debe ser categorizado como navegador"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_obvious_keylogger_should_be_flagged(self, process_validator):
        """
        TEST RED #3: Proceso con nombre 'keylogger.exe' debe ser flagueado.

        Cualquier proceso llamado 'keylogger.exe' es obviamente malicioso.
        No hay razón legítima para este nombre.
        """
        # Arrange - Malware obvio
        process_data = {
            "name": "keylogger.exe",
            "path": "C:\\Users\\Admin\\Desktop\\keylogger.exe",
            "pid": 6666,
            "cpu_percent": 25.0,
            "memory_mb": 50.0,
            "digital_signature": None,  # Sin firma
            "started_at": datetime.now().isoformat(),
        }

        # Act
        result = process_validator.is_process_safe(process_data)

        # Assert - Debe ser detectado como peligroso
        assert (
            result["is_safe"] is False
        ), "Keylogger.exe debe ser flagueado como peligroso"
        assert (
            result["confidence"] <= 0.1
        ), f"Confianza muy baja esperada (<=0.1), got {result['confidence']}"
        assert (
            result["threat_score"] >= 0.9
        ), f"Score alto de amenaza esperado (>=0.9), got {result['threat_score']}"
        assert (
            "obvious_malware" in result["threat_indicators"]
        ), "Debe detectar malware obvio"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    @pytest.mark.parametrize(
        "process_name,expected_safe,category",
        [
            # Procesos del sistema - seguros
            ("explorer.exe", True, "system_process"),
            ("dwm.exe", True, "system_process"),
            ("calc.exe", True, "system_process"),
            # Navegadores - seguros
            ("firefox.exe", True, "browser"),
            ("msedge.exe", True, "browser"),
            ("opera.exe", True, "browser"),
            # Productividad - seguros
            ("winword.exe", True, "productivity"),
            ("excel.exe", True, "productivity"),
            ("code.exe", True, "productivity"),
            # Gaming - seguros
            ("steam.exe", True, "gaming"),
            ("discord.exe", True, "gaming"),
            # Malware obvio - peligrosos
            ("stealer.exe", False, "malware"),
            ("backdoor.exe", False, "malware"),
            ("trojan.exe", False, "malware"),
        ],
    )
    def test_process_categorization_accuracy(
        self, process_validator, process_name, expected_safe, category
    ):
        """
        TEST RED #4: Categorización precisa de múltiples procesos.

        Test parametrizado que verifica clasificación correcta
        de procesos conocidos según sus categorías.
        """
        # Arrange
        process_data = {
            "name": process_name,
            "path": f"C:\\Program Files\\SomeApp\\{process_name}",
            "pid": 1000,
            "cpu_percent": 5.0,
            "memory_mb": 100.0,
        }

        # Act
        result = process_validator.is_process_safe(process_data)

        # Assert - Verificar clasificación correcta
        assert (
            result["is_safe"] == expected_safe
        ), f"{process_name} clasificación incorrecta"

        if expected_safe:
            assert (
                result["confidence"] >= 0.7
            ), f"Confianza alta para proceso seguro {process_name}"
            assert (
                result["threat_score"] <= 0.2
            ), f"Score bajo de amenaza para {process_name}"
        else:
            assert (
                result["confidence"] <= 0.3
            ), f"Confianza baja para proceso peligroso {process_name}"
            assert (
                result["threat_score"] >= 0.7
            ), f"Score alto de amenaza para {process_name}"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_suspicious_location_should_lower_trust(self, process_validator):
        """
        TEST RED #5: Proceso legítimo en ubicación sospechosa debe bajar confianza.
        
        Incluso 'notepad.exe' es sospechoso si está en C:\\Temp\\
        Los atacantes a menudo copian nombres legítimos.
        """
        # Arrange - Notepad en ubicación sospechosa
        process_data = {
            "name": "notepad.exe",  # Nombre legítimo
            "path": "C:\\Temp\\notepad.exe",  # 🚨 Ubicación sospechosa
            "pid": 7777,
            "cpu_percent": 15.0,  # CPU alta para notepad
            "memory_mb": 100.0,  # Memoria alta para notepad
            "digital_signature": None,  # Sin firma
        }

        # Act
        result = process_validator.is_process_safe(process_data)

        # Assert - Confianza reducida por ubicación
        assert (
            result["is_safe"] is False
        ), "Notepad en ubicación sospechosa debe ser flagueado"
        assert (
            result["confidence"] <= 0.5
        ), f"Confianza reducida por ubicación, got {result['confidence']}"
        assert (
            "suspicious_location" in result["threat_indicators"]
        ), "Debe detectar ubicación sospechosa"
        assert (
            "impersonation_attempt" in result["threat_indicators"]
        ), "Puede ser intento de suplantación"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_unknown_process_should_require_investigation(self, process_validator):
        """
        TEST RED #6: Proceso desconocido debe requerir investigación.

        Procesos no conocidos no son automáticamente maliciosos,
        pero requieren análisis adicional antes de ser confiables.
        """
        # Arrange - Proceso completamente desconocido
        process_data = {
            "name": "myapp.exe",
            "path": "C:\\Users\\John\\Documents\\myapp.exe",
            "pid": 8888,
            "cpu_percent": 2.0,
            "memory_mb": 30.0,
            "digital_signature": "Unknown Developer",
        }

        # Act
        result = process_validator.is_process_safe(process_data)

        # Assert - Estado neutral, requiere más análisis
        assert (
            result["is_safe"] is None
        ), "Proceso desconocido debe tener estado neutral"
        assert (
            0.3 <= result["confidence"] <= 0.7
        ), f"Confianza neutral para desconocido, got {result['confidence']}"
        assert (
            result["requires_investigation"] is True
        ), "Debe requerir investigación adicional"
        assert result["recommendation"] == "monitor", "Debe recomendar monitoreo"

    @pytest.mark.tdd
    @pytest.mark.safe_process
    def test_digital_signature_validation(self, process_validator):
        """
        TEST RED #7: Firma digital debe afectar validación de seguridad.

        Procesos firmados por Microsoft, Google, Adobe, etc.
        tienen mayor credibilidad que procesos sin firmar.
        """
        # Arrange - Mismo proceso con diferentes firmas
        signed_process = {
            "name": "app.exe",
            "path": "C:\\Program Files\\MyApp\\app.exe",
            "digital_signature": "Microsoft Corporation",  # 🏆 Confiable
            "signature_valid": True,
        }

        unsigned_process = {
            "name": "app.exe",
            "path": "C:\\Program Files\\MyApp\\app.exe",
            "digital_signature": None,  # ⚠️ Sin firma
            "signature_valid": False,
        }

        # Act
        signed_result = process_validator.is_process_safe(signed_process)
        unsigned_result = process_validator.is_process_safe(unsigned_process)

        # Assert - Firma debe mejorar confianza
        assert (
            signed_result["confidence"] > unsigned_result["confidence"]
        ), "Firma debe aumentar confianza"
        assert (
            signed_result["threat_score"] < unsigned_result["threat_score"]
        ), "Firma debe reducir amenaza"
        assert (
            "trusted_signature" in signed_result["trust_factors"]
        ), "Debe reconocer firma confiable"
