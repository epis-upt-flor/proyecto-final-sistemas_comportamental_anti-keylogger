"""
TDD #2: Suspicious Port Detection for Network Security
======================================================

Test-Driven Development para la detección de conexiones de red
sospechosas que pueden indicar exfiltración de datos robados
por keyloggers a servidores de atacantes.

Este test detecta cuando malware envía información capturada
a través de puertos no estándar comúnmente usados por atacantes.
"""

import sys
from pathlib import Path

# Agregar el directorio raíz al path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import pytest
from datetime import datetime, timedelta

# 🔧 TDD #2 REFACTOR: Importar NetworkAnalyzer REAL del antivirus
from plugins.detectors.network_detector.network_analyzer import NetworkAnalyzer


class TestSuspiciousPortDetectionTDD:
    """
    Suite de tests TDD para detección de puertos sospechosos.

    Implementa detección de conexiones de red que pueden indicar
    exfiltración de datos o comunicación con servidores C&C.
    """

    @pytest.fixture
    def network_detector(self):
        """Instancia del NetworkAnalyzer REAL del antivirus para tests"""
        config = {
            "suspicious_ports": {
                "high_risk": [1337, 4444, 5555, 31337, 6667],
                "medium_risk": [8080, 9999, 1234],
                "legitimate": [80, 443, 53, 3306, 5432, 25, 110, 993, 995],
            },
            "thresholds": {
                "high_risk_score": 0.8,
                "medium_risk_score": 0.5,
                "legitimate_score": 0.1,
            },
        }
        # ✅ Usar NetworkAnalyzer REAL del antivirus
        return NetworkAnalyzer(config)

    # ========================
    # FASE RED: Tests que deben fallar inicialmente
    # ========================

    @pytest.mark.tdd
    @pytest.mark.network_security
    def test_suspicious_port_4444_should_be_flagged(self, network_detector):
        """
        TEST RED #1: Puerto 4444 (Metasploit handler) debe ser detectado.

        Puerto 4444 es usado comúnmente por:
        - Metasploit reverse shells
        - Backdoors simples
        - Keyloggers para enviar datos

        Este test DEBE FALLAR porque analyze_port_usage() no existe.
        """
        # Arrange - Conexión sospechosa al puerto 4444
        network_data = {
            "process_name": "suspicious.exe",
            "connections": [
                {
                    "local_port": 49152,
                    "remote_host": "192.168.1.100",
                    "remote_port": 4444,
                    "state": "ESTABLISHED",
                    "timestamp": datetime.now().isoformat(),
                }
            ],
        }

        # Act - Esta función debe implementarse con TDD
        result = network_detector.analyze_port_usage(network_data)

        # Assert - Debe detectar como altamente sospechoso
        assert (
            result["is_suspicious"] is True
        ), "Puerto 4444 debe ser detectado como sospechoso"
        assert (
            result["risk_score"] >= 0.8
        ), f"Score alto esperado (>=0.8), got {result['risk_score']}"
        assert (
            4444 in result["suspicious_ports"]
        ), "Puerto 4444 debe estar en lista sospechosa"
        assert (
            "c2_communication" in result["threat_indicators"]
        ), "Debe identificar comunicación C&C"

    @pytest.mark.tdd
    @pytest.mark.network_security
    def test_legitimate_https_port_443_should_pass(self, network_detector):
        """
        TEST RED #2: Puerto 443 (HTTPS) debe ser considerado legítimo.

        Puerto 443 es estándar para:
        - Navegación web segura (Google, Facebook, etc.)
        - APIs HTTPS legítimas
        - Actualizaciones de software

        NO debe generar alertas falsas.
        """
        # Arrange - Conexión legítima HTTPS
        network_data = {
            "process_name": "chrome.exe",
            "connections": [
                {
                    "local_port": 49180,
                    "remote_host": "www.google.com",
                    "remote_port": 443,
                    "state": "ESTABLISHED",
                    "timestamp": datetime.now().isoformat(),
                }
            ],
        }

        # Act
        result = network_detector.analyze_port_usage(network_data)

        # Assert - NO debe ser sospechoso
        assert result["is_suspicious"] is False, "Puerto 443 no debe ser sospechoso"
        assert (
            result["risk_score"] < 0.3
        ), f"Score bajo esperado (<0.3), got {result['risk_score']}"
        assert 443 not in result.get(
            "suspicious_ports", []
        ), "Puerto 443 no debe estar en lista sospechosa"
        assert (
            len(result["threat_indicators"]) == 0
        ), "No debe haber indicadores de amenaza"

    @pytest.mark.tdd
    @pytest.mark.network_security
    @pytest.mark.parametrize(
        "port,expected_risk",
        [
            (1337, "high"),  # Leet speak - hacking
            (4444, "high"),  # Metasploit handler
            (5555, "high"),  # Common backdoor
            (8080, "medium"),  # Alt HTTP (sospechoso)
            (9999, "medium"),  # Dev/testing port
            (80, "low"),  # HTTP legítimo
            (443, "low"),  # HTTPS legítimo
            (3306, "low"),  # MySQL legítimo
        ],
    )
    def test_port_classification_accuracy(self, network_detector, port, expected_risk):
        """
        TEST RED #3: Clasificación correcta de múltiples puertos.

        Test parametrizado que verifica la clasificación precisa
        de diferentes puertos según su nivel de riesgo conocido.
        """
        # Arrange
        network_data = {
            "process_name": "test_app.exe",
            "connections": [
                {
                    "local_port": 50000,
                    "remote_host": "10.0.0.1",
                    "remote_port": port,
                    "state": "ESTABLISHED",
                    "timestamp": datetime.now().isoformat(),
                }
            ],
        }

        # Act
        result = network_detector.analyze_port_usage(network_data)

        # Assert - Verificar clasificación correcta
        if expected_risk == "high":
            assert (
                result["is_suspicious"] is True
            ), f"Puerto {port} debe ser de alto riesgo"
            assert result["risk_score"] >= 0.8, f"Score alto para puerto {port}"
        elif expected_risk == "medium":
            assert (
                result["is_suspicious"] is True
            ), f"Puerto {port} debe ser de medio riesgo"
            assert 0.4 <= result["risk_score"] < 0.8, f"Score medio para puerto {port}"
        else:  # low risk
            assert (
                result["is_suspicious"] is False
            ), f"Puerto {port} debe ser de bajo riesgo"
            assert result["risk_score"] < 0.3, f"Score bajo para puerto {port}"

    @pytest.mark.tdd
    @pytest.mark.network_security
    def test_multiple_suspicious_connections_aggregate_risk(self, network_detector):
        """
        TEST RED #4: Múltiples conexiones sospechosas aumentan el riesgo.

        Keyloggers sofisticados pueden usar múltiples puertos
        para redundancia o diferentes tipos de datos.
        """
        # Arrange - Múltiples conexiones sospechosas
        network_data = {
            "process_name": "malware.exe",
            "connections": [
                {"remote_port": 1337, "state": "ESTABLISHED"},  # High risk
                {"remote_port": 4444, "state": "ESTABLISHED"},  # High risk
                {"remote_port": 8080, "state": "ESTABLISHED"},  # Medium risk
            ],
        }

        # Act
        result = network_detector.analyze_port_usage(network_data)

        # Assert - Riesgo agregado debe ser muy alto
        assert (
            result["is_suspicious"] is True
        ), "Múltiples puertos sospechosos deben alertar"
        assert (
            result["risk_score"] >= 0.9
        ), f"Score muy alto para múltiples puertos, got {result['risk_score']}"
        assert (
            len(result["suspicious_ports"]) == 3
        ), "Debe detectar los 3 puertos sospechosos"
        assert (
            "multiple_suspicious_ports" in result["threat_indicators"]
        ), "Debe detectar patrón múltiple"

    @pytest.mark.tdd
    @pytest.mark.network_security
    def test_connection_frequency_analysis(self, network_detector):
        """
        TEST RED #5: Conexiones muy frecuentes indican beaconing.

        Keyloggers pueden enviar datos cada pocos minutos/segundos
        creando un patrón de "beaconing" típico de malware.
        """
        # Arrange - Conexiones muy frecuentes (cada 5 segundos para beaconing agresivo)
        base_time = datetime.now()
        connections = []

        for i in range(10):  # 10 conexiones en 45 segundos (cada 5 segundos)
            connections.append(
                {
                    "remote_port": 8080,
                    "remote_host": "suspicious-server.com",
                    "state": "ESTABLISHED",
                    "timestamp": (base_time + timedelta(seconds=5 * i)).isoformat(),
                }
            )

        network_data = {"process_name": "beacon.exe", "connections": connections}

        # Act
        result = network_detector.analyze_port_usage(network_data)

        # Assert - Debe detectar patrón de beaconing
        assert (
            result["is_suspicious"] is True
        ), "Conexiones frecuentes deben ser sospechosas"
        assert (
            "beaconing_pattern" in result["threat_indicators"]
        ), "Debe detectar patrón de beaconing"
        assert (
            result["connection_frequency"] >= 0.2
        ), "Debe calcular frecuencia alta (>0.2 conn/sec)"

    @pytest.mark.tdd
    @pytest.mark.network_security
    def test_no_connections_should_return_neutral(self, network_detector):
        """
        TEST RED #6: Sin conexiones debe retornar resultado neutral.

        Caso edge: proceso sin actividad de red detectada.
        """
        # Arrange
        network_data = {
            "process_name": "offline_app.exe",
            "connections": [],  # Sin conexiones
        }

        # Act
        result = network_detector.analyze_port_usage(network_data)

        # Assert - Neutral por defecto
        assert result["is_suspicious"] is False, "Sin conexiones no debe ser sospechoso"
        assert (
            result["risk_score"] == 0.0
        ), f"Score neutral esperado (0.0), got {result['risk_score']}"
        assert result["suspicious_ports"] == [], "Sin puertos sospechosos"
        assert result["threat_indicators"] == [], "Sin indicadores de amenaza"
