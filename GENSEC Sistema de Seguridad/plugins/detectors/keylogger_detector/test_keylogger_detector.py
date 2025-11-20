#!/usr/bin/env python3
"""
Test Script para Keylogger Detector
===================================

Script para probar el detector especializado contra los keyloggers reales encontrados.
Simula el comportamiento de keyloggers conocidos para validar la detección.
"""

import sys
import os
import time
import tempfile
import subprocess
import threading
from pathlib import Path

# Agregar el directorio raíz del proyecto al path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from plugins.detectors.keylogger_detector import KeyloggerDetector


class KeyloggerSimulator:
    """Simula comportamientos de keyloggers para testing"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.simulated_processes = []

    def simulate_harem_keylogger(self):
        """Simula el comportamiento de Harem.c"""
        print("🧪 Simulando Harem.c keylogger...")

        # Crear archivo readme.txt (patrón de Harem.c)
        readme_file = os.path.join(self.temp_dir, "readme.txt")
        with open(readme_file, "w") as f:
            f.write("[LEFT-CLICK] Hello World [RIGHT-CLICK]\n")
            f.write("Keystroke captured at: " + str(time.time()) + "\n")

        return {
            "pid": 1234,
            "name": "suspicious_process.exe",
            "cmd": ["./keylogger.exe"],
            "cwd": self.temp_dir,
            "created_files": [readme_file],
        }

    def simulate_ghost_writer(self):
        """Simula el comportamiento de Ghost_Writer.cs"""
        print("🧪 Simulando Ghost_Writer keylogger...")

        # Crear archivos típicos de Ghost_Writer
        text_data_file = os.path.join(self.temp_dir, "Text_Data.txt")
        image_dir = os.path.join(self.temp_dir, "Image_Data")
        os.makedirs(image_dir, exist_ok=True)

        with open(text_data_file, "w") as f:
            f.write("2025-10-22 15:30:45\n")
            f.write("username: testuser\n")
            f.write("keystrokes: password123\n")

        # Simular screenshot
        screenshot_file = os.path.join(image_dir, "screenshot_001.png")
        with open(screenshot_file, "wb") as f:
            f.write(b"fake_png_data")

        return {
            "pid": 5678,
            "name": "Ghost_Writer.exe",
            "cmd": ["./Ghost_Writer.exe"],
            "cwd": self.temp_dir,
            "created_files": [text_data_file, screenshot_file],
        }

    def simulate_encrypted_keylogger(self):
        """Simula el comportamiento de EncryptedKeylogger.py"""
        print("🧪 Simulando EncryptedKeylogger...")

        # Crear múltiples archivos como el keylogger Python
        files = {
            "key_log.txt": "encrypted_keystrokes_data",
            "syseminfo.txt": "system_information_dump",
            "clipboard.txt": "clipboard_captured_data",
            "audio.wav": "fake_audio_data",
            "screenshot.png": "fake_screenshot_data",
        }

        created_files = []
        for filename, content in files.items():
            file_path = os.path.join(self.temp_dir, filename)
            with open(file_path, "w") as f:
                f.write(content + "\n" + str(time.time()))
            created_files.append(file_path)

        return {
            "pid": 9999,
            "name": "python.exe",
            "cmd": ["python", "EncryptedKeylogger.py"],
            "cwd": self.temp_dir,
            "created_files": created_files,
        }


def test_keylogger_detector():
    """Función principal de testing"""
    print("🔍 TESTING KEYLOGGER DETECTOR v2.0")
    print("=" * 50)

    # Configuración del detector
    config = {
        "keylogger_detector": {
            "sensitivity": "high",
            "monitor_hooks": True,
            "monitor_files": True,
            "monitor_stealth": True,
        },
        "performance": {"max_concurrent_analyses": 3, "analysis_timeout_ms": 5000},
    }

    # Inicializar detector
    detector = KeyloggerDetector(config)
    detector.start()

    # Crear simulador
    simulator = KeyloggerSimulator()

    # Tests individuales
    test_results = {
        "harem_detected": False,
        "ghost_writer_detected": False,
        "encrypted_keylogger_detected": False,
        "false_positives": 0,
    }

    print("\n🧪 Test 1: Harem.c Keylogger")
    print("-" * 30)
    harem_data = simulator.simulate_harem_keylogger()
    threats = detector.analyze_process_for_keylogger(harem_data)

    if threats:
        print("✅ DETECTED: Harem keylogger")
        print(f"   Threat: {threats[0]['type']}")
        print(f"   Score: {threats[0]['risk_score']:.2f}")
        print(f"   Reasons: {', '.join(threats[0]['detection_reasons'])}")
        test_results["harem_detected"] = True
    else:
        print("❌ NOT DETECTED: Harem keylogger")

    print("\n🧪 Test 2: Ghost_Writer Keylogger")
    print("-" * 30)
    ghost_data = simulator.simulate_ghost_writer()
    threats = detector.analyze_process_for_keylogger(ghost_data)

    if threats:
        print("✅ DETECTED: Ghost_Writer keylogger")
        print(f"   Threat: {threats[0]['type']}")
        print(f"   Score: {threats[0]['risk_score']:.2f}")
        print(f"   Reasons: {', '.join(threats[0]['detection_reasons'])}")
        test_results["ghost_writer_detected"] = True
    else:
        print("❌ NOT DETECTED: Ghost_Writer keylogger")

    print("\n🧪 Test 3: EncryptedKeylogger")
    print("-" * 30)
    encrypted_data = simulator.simulate_encrypted_keylogger()
    threats = detector.analyze_process_for_keylogger(encrypted_data)

    if threats:
        print("✅ DETECTED: EncryptedKeylogger")
        print(f"   Threat: {threats[0]['type']}")
        print(f"   Score: {threats[0]['risk_score']:.2f}")
        print(f"   Reasons: {', '.join(threats[0]['detection_reasons'])}")
        test_results["encrypted_keylogger_detected"] = True
    else:
        print("❌ NOT DETECTED: EncryptedKeylogger")

    # Test de proceso legítimo (evitar falsos positivos)
    print("\n🧪 Test 4: Proceso Legítimo (Control)")
    print("-" * 30)
    legitimate_data = {
        "pid": 1111,
        "name": "notepad.exe",
        "cmd": ["notepad.exe"],
        "cwd": "C:\\Windows\\System32",
    }
    threats = detector.analyze_process_for_keylogger(legitimate_data)

    if threats:
        print("⚠️ FALSE POSITIVE: Proceso legítimo detectado como keylogger")
        test_results["false_positives"] += 1
    else:
        print("✅ CORRECT: Proceso legítimo no detectado")

    # Mostrar estadísticas del detector
    print("\n📊 Estadísticas del Detector")
    print("-" * 30)
    stats = detector.get_stats()
    keylogger_stats = stats.get("keylogger_specific", {})

    for key, value in keylogger_stats.items():
        print(f"   {key}: {value}")

    # Resumen final
    print("\n🎯 RESUMEN DE RESULTADOS")
    print("=" * 50)

    detected = sum(
        [
            test_results["harem_detected"],
            test_results["ghost_writer_detected"],
            test_results["encrypted_keylogger_detected"],
        ]
    )

    detection_rate = (detected / 3) * 100

    print(f"Keyloggers detectados: {detected}/3 ({detection_rate:.1f}%)")
    print(f"Falsos positivos: {test_results['false_positives']}")

    if detection_rate >= 80 and test_results["false_positives"] == 0:
        print("🎉 RESULTADO: DETECTOR APROBADO")
    elif detection_rate >= 60:
        print("⚠️ RESULTADO: DETECTOR NECESITA MEJORAS")
    else:
        print("❌ RESULTADO: DETECTOR NECESITA RECONFIGURACIÓN")

    # Limpiar
    detector.stop()

    return test_results


def test_with_real_keylogger_signatures():
    """Test adicional con firmas reales de keyloggers"""
    print("\n🔬 TESTING CON FIRMAS REALES")
    print("-" * 30)

    # Configurar detector en modo paranoid para este test
    config = {
        "keylogger_detector": {
            "sensitivity": "paranoid",
            "monitor_hooks": True,
            "monitor_files": True,
            "monitor_stealth": True,
        }
    }

    detector = KeyloggerDetector(config)
    detector.start()

    # Datos basados en firmas reales extraídas de los keyloggers
    real_signatures = [
        {
            "name": "SetWindowsHookEx signature",
            "process_data": {
                "pid": 2222,
                "name": "system32.exe",  # Nombre sospechoso
                "cmd": ["system32.exe"],
                "cwd": "C:\\Users\\User\\Documents",  # Ubicación sospechosa
            },
        },
        {
            "name": "Multiple log files signature",
            "process_data": {
                "pid": 3333,
                "name": "svchost.exe",  # Nombre que imita proceso sistema
                "cmd": ["svchost.exe"],
                "cwd": "C:\\Users\\User\\AppData\\Roaming",
            },
        },
    ]

    for signature in real_signatures:
        print(f"\n   Testing: {signature['name']}")
        threats = detector.analyze_process_for_keylogger(signature["process_data"])

        if threats:
            print(f"   ✅ Detected with score: {threats[0]['risk_score']:.2f}")
        else:
            print("   ❌ Not detected")

    detector.stop()


if __name__ == "__main__":
    print("🛡️ UNIFIED ANTIVIRUS - KEYLOGGER DETECTOR TEST")
    print("Probando detector contra keyloggers reales encontrados")
    print("=" * 60)

    try:
        # Test principal
        results = test_keylogger_detector()

        # Test adicional con firmas
        test_with_real_keylogger_signatures()

        print("\n🏁 Testing completado exitosamente")

    except Exception as e:
        print(f"\n❌ Error durante testing: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
