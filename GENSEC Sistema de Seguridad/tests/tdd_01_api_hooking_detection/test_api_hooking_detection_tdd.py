"""
TDD #1: API Hooking Detection for Keyloggers
===========================================

Test-Driven Development para la detección de APIs sospechosas
utilizadas por keyloggers reales como SetWindowsHookEx y GetAsyncKeyState.

Este es el test MÁS CRÍTICO del antivirus porque detecta la técnica
principal que usan los keyloggers para interceptar pulsaciones de teclado.
"""

import sys
import os
from pathlib import Path

# Agregar el directorio raíz al path para importar plugins
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import pytest
from plugins.detectors.keylogger_detector.keylogger_detector import KeyloggerDetector


class TestAPIHookingDetectionTDD:
    """
    Suite de tests TDD para detección de APIs de hooking.

    Implementa el ciclo Red-Green-Refactor para desarrollar
    la funcionalidad de detección de APIs sospechosas paso a paso.
    """

    @pytest.fixture
    def detector_config(self):
        """Configuración básica para el detector"""
        return {
            "keylogger_detector": {
                "sensitivity": "high",
                "monitor_hooks": True,
                "api_analysis_enabled": True,
            }
        }

    @pytest.fixture
    def keylogger_detector(self, detector_config):
        """Instancia del detector para tests"""
        return KeyloggerDetector(detector_config)

    # ========================
    # FASE RED: Tests que deben fallar inicialmente
    # ========================

    @pytest.mark.tdd
    @pytest.mark.api_detection
    def test_detect_hooking_apis_should_return_high_risk(self, keylogger_detector):
        """
        TEST RED #1: APIs críticas de hooking deben generar alto riesgo.

        APIs que usan keyloggers REALES:
        - SetWindowsHookEx: Hook principal para interceptar teclas (Harem.c)
        - GetAsyncKeyState: Leer estado de teclas (Ghost_Writer.cs)
        - GetForegroundWindow: Ventana activa para context

        Este test DEBE FALLAR inicialmente porque analyze_api_usage() no existe.
        """
        # Arrange - Simular proceso sospechoso con APIs críticas
        process_data = {
            "name": "suspicious_keylogger.exe",
            "pid": 1337,
            "apis_called": [
                "SetWindowsHookEx",  # 🚨 CRÍTICA - Hook de teclado
                "GetAsyncKeyState",  # 🚨 CRÍTICA - Estado de teclas
                "GetForegroundWindow",  # 🚨 CRÍTICA - Ventana activa
            ],
        }

        # Act - Esta función debe implementarse con TDD
        result = keylogger_detector.analyze_api_usage(process_data)

        # Assert - Verificar detección correcta
        assert result["is_suspicious"] is True, "APIs de hooking deben ser detectadas"
        assert (
            result["risk_score"] >= 0.8
        ), f"Score debe ser alto (>=0.8), got {result['risk_score']}"
        assert (
            "api_hooking" in result["threat_indicators"]
        ), "Debe identificar hooking como amenaza"
        assert len(result["suspicious_apis"]) >= 3, "Debe detectar las 3 APIs críticas"

    @pytest.mark.tdd
    @pytest.mark.api_detection
    def test_detect_file_logging_apis_should_return_medium_risk(
        self, keylogger_detector
    ):
        """
        TEST RED #2: APIs de logging deben generar riesgo medio.

        Keyloggers también usan APIs para escribir logs:
        - CreateFileA/W: Crear archivo de log
        - WriteFile: Escribir datos capturados
        - GetSystemTime: Timestamp para entries
        """
        # Arrange - Proceso con APIs de logging (menos críticas)
        process_data = {
            "name": "data_logger.exe",
            "pid": 2468,
            "apis_called": [
                "CreateFileA",  # 📝 Crear archivo
                "WriteFile",  # 📝 Escribir datos
                "GetSystemTime",  # 📝 Timestamp
            ],
        }

        # Act
        result = keylogger_detector.analyze_api_usage(process_data)

        # Assert - Riesgo medio (no tan crítico como hooking)
        assert result["is_suspicious"] is True, "APIs de logging deben ser sospechosas"
        assert (
            0.4 <= result["risk_score"] < 0.8
        ), f"Score medio esperado [0.4, 0.8), got {result['risk_score']}"
        assert (
            "file_logging" in result["threat_indicators"]
        ), "Debe identificar logging como sospechoso"

    @pytest.mark.tdd
    @pytest.mark.api_detection
    def test_legitimate_apis_should_return_low_risk(self, keylogger_detector):
        """
        TEST RED #3: APIs legítimas NO deben ser flagueadas.

        Software normal usa APIs que NO son sospechosas:
        - CreateWindow: Crear ventanas normales
        - ShowWindow: Mostrar UI
        - GetMessage: Loop de mensajes estándar
        """
        # Arrange - Aplicación legítima (ej: Notepad)
        process_data = {
            "name": "notepad.exe",
            "pid": 1234,
            "apis_called": [
                "CreateWindow",  # ✅ Legítima - UI normal
                "ShowWindow",  # ✅ Legítima - Mostrar ventana
                "GetMessage",  # ✅ Legítima - Loop de mensajes
                "UpdateWindow",  # ✅ Legítima - Actualizar UI
            ],
        }

        # Act
        result = keylogger_detector.analyze_api_usage(process_data)

        # Assert - NO debe ser detectado como amenaza
        assert (
            result["is_suspicious"] is False
        ), "APIs legítimas no deben ser sospechosas"
        assert (
            result["risk_score"] < 0.3
        ), f"Score bajo esperado (<0.3), got {result['risk_score']}"
        assert (
            len(result["threat_indicators"]) == 0
        ), "No debe haber indicadores de amenaza"

    @pytest.mark.tdd
    @pytest.mark.api_detection
    def test_mixed_apis_should_calculate_weighted_score(self, keylogger_detector):
        """
        TEST RED #4: Combinación de APIs debe usar scoring ponderado.

        Proceso que usa TANTO APIs legítimas como sospechosas.
        El score debe reflejar la proporción y peso de cada tipo.
        """
        # Arrange - Mix de APIs (realista)
        process_data = {
            "name": "mixed_app.exe",
            "pid": 9999,
            "apis_called": [
                "SetWindowsHookEx",  # 🚨 CRÍTICA (peso 0.9)
                "CreateWindow",  # ✅ Legítima (peso 0.1)
                "WriteFile",  # 📝 Sospechosa (peso 0.6)
                "ShowWindow",  # ✅ Legítima (peso 0.1)
            ],
        }

        # Act
        result = keylogger_detector.analyze_api_usage(process_data)

        # Assert - Score ponderado (debe ser sospechoso por SetWindowsHookEx)
        assert result["is_suspicious"] is True, "SetWindowsHookEx debe dominar el score"
        assert (
            0.6 <= result["risk_score"] < 0.9
        ), f"Score ponderado esperado [0.6, 0.9), got {result['risk_score']}"
        assert "api_hooking" in result["threat_indicators"], "Debe detectar hooking"
        assert (
            "legitimate_usage" in result["details"]
        ), "Debe reconocer uso legítimo también"

    @pytest.mark.tdd
    @pytest.mark.api_detection
    def test_empty_api_list_should_return_neutral(self, keylogger_detector):
        """
        TEST RED #5: Lista vacía de APIs debe retornar resultado neutral.

        Caso edge: proceso sin APIs detectadas.
        """
        # Arrange
        process_data = {
            "name": "unknown_process.exe",
            "pid": 5555,
            "apis_called": [],  # Sin APIs
        }

        # Act
        result = keylogger_detector.analyze_api_usage(process_data)

        # Assert - Neutral/seguro por defecto
        assert result["is_suspicious"] is False, "Sin APIs no debe ser sospechoso"
        assert (
            result["risk_score"] == 0.0
        ), f"Score neutral esperado (0.0), got {result['risk_score']}"
        assert result["threat_indicators"] == [], "Sin indicadores de amenaza"
