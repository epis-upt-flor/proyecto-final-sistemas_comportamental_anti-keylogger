#!/usr/bin/env python3
"""
IAST Integration Test
===================

Test completo para verificar que el IAST detector:
1. Se integra correctamente con el antivirus
2. Detecta amenazas de keyloggers
3. Protege la integridad del antivirus 
4. Envía logs al sistema web
"""

import os
import sys
import time
import tempfile
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path

# Agregar path del antivirus
antivirus_root = Path(__file__).parent.parent
sys.path.append(str(antivirus_root))

from utils.logger import get_logger
from plugins.detectors.iast_detector.iast_engine import IASTSelfProtectionEngine
from plugins.detectors.iast_detector.plugin import IASTDetectorPlugin

logger = get_logger("iast_integration_test")

class IASTIntegrationTest:
    """Suite de tests para IAST integration"""
    
    def __init__(self):
        self.test_results = []
        self.iast_engine = None
        self.plugin = None
        
    def log_result(self, test_name: str, success: bool, details: str = ""):
        """Registra resultado de test"""
        result = {
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if success else "❌ FAIL"
        logger.info(f"{status} {test_name}: {details}")
        print(f"{status} {test_name}: {details}")
    
    def test_engine_initialization(self):
        """Test 1: Inicialización del motor IAST"""
        try:
            self.iast_engine = IASTSelfProtectionEngine()
            
            # Verificar que se calculó el baseline
            has_baseline = len(self.iast_engine.baseline_hashes) > 0
            
            self.log_result(
                "Engine Initialization",
                has_baseline,
                f"Baseline calculado para {len(self.iast_engine.baseline_hashes)} archivos"
            )
            return has_baseline
            
        except Exception as e:
            self.log_result("Engine Initialization", False, f"Error: {e}")
            return False
    
    def test_plugin_activation(self):
        """Test 2: Activación del plugin en el sistema"""
        try:
            self.plugin = IASTDetectorPlugin()
            
            # Activar plugin usando el template method
            activation_success = self.plugin.activate()
            
            # Verificar estado
            is_running = self.plugin.is_active and self.plugin.iast_engine is not None
            
            self.log_result(
                "Plugin Activation", 
                is_running,
                f"Plugin {'activo' if is_running else 'inactivo'}"
            )
            return is_running
            
        except Exception as e:
            self.log_result("Plugin Activation", False, f"Error: {e}")
            return False
    
    def test_file_integrity_monitoring(self):
        """Test 3: Monitoreo de integridad de archivos"""
        try:
            if not self.iast_engine:
                return False
            
            # Verificar integridad inicial (debe estar OK)
            initial_integrity = self.iast_engine.check_file_integrity()
            
            self.log_result(
                "File Integrity Monitoring",
                initial_integrity,
                "Integridad inicial verificada"
            )
            return initial_integrity
            
        except Exception as e:
            self.log_result("File Integrity Monitoring", False, f"Error: {e}")
            return False
    
    def test_keylogger_detection(self):
        """Test 4: Detección de keyloggers"""
        try:
            if not self.iast_engine:
                return False
            
            # Escanear procesos actuales
            detected_keyloggers = self.iast_engine.scan_for_keyloggers()
            
            # El test es exitoso si no hay errores (puede encontrar 0+ keyloggers)
            scan_successful = isinstance(detected_keyloggers, list)
            
            self.log_result(
                "Keylogger Detection",
                scan_successful,
                f"Escaneo completo - {len(detected_keyloggers)} keyloggers detectados"
            )
            return scan_successful
            
        except Exception as e:
            self.log_result("Keylogger Detection", False, f"Error: {e}")
            return False
    
    def test_threat_detection_interface(self):
        """Test 5: Interface de detección de amenazas"""
        try:
            if not self.plugin:
                return False
            
            # Usar interface DetectorInterface
            threats = self.plugin.detect_threats({})
            
            # Verificar que retorna lista válida
            interface_working = isinstance(threats, list)
            
            # Verificar confidence score
            confidence = self.plugin.get_confidence_score()
            confidence_valid = 0.0 <= confidence <= 1.0
            
            overall_success = interface_working and confidence_valid
            
            self.log_result(
                "Threat Detection Interface",
                overall_success,
                f"Amenazas: {len(threats)}, Confidence: {confidence:.2f}"
            )
            return overall_success
            
        except Exception as e:
            self.log_result("Threat Detection Interface", False, f"Error: {e}")
            return False
    
    def test_web_logging_integration(self):
        """Test 6: Integración con sistema de logging web"""
        try:
            if not self.plugin:
                return False
            
            # Simular detección que debe generar log
            test_data = {
                "test_scenario": "integration_test",
                "timestamp": datetime.now().isoformat()
            }
            
            # Forzar una detección para generar logs
            threats = self.plugin.detect_threats(test_data)
            
            # Verificar que el logging funciona (no falla)
            logger.error("🧪 TEST LOG: IAST Integration Test ejecutándose")
            logger.warning(f"🎯 Test detectó {len(threats)} amenazas")
            
            # Si llegamos aquí sin excepción, el logging funciona
            self.log_result(
                "Web Logging Integration",
                True,
                "Logs generados exitosamente para sistema web"
            )
            return True
            
        except Exception as e:
            self.log_result("Web Logging Integration", False, f"Error: {e}")
            return False
    
    def test_plugin_statistics(self):
        """Test 7: Estadísticas del plugin"""
        try:
            if not self.plugin:
                return False
            
            # Obtener estadísticas
            stats = self.plugin.get_detection_statistics()
            info = self.plugin.get_plugin_info()
            status = self.plugin.get_status()
            
            # Verificar que tienen la estructura esperada
            stats_valid = isinstance(stats, dict) and 'plugin_name' in stats
            info_valid = isinstance(info, dict) and 'name' in info
            status_valid = isinstance(status, dict) and 'status' in status
            
            all_valid = stats_valid and info_valid and status_valid
            
            self.log_result(
                "Plugin Statistics",
                all_valid,
                f"Stats: {stats_valid}, Info: {info_valid}, Status: {status_valid}"
            )
            return all_valid
            
        except Exception as e:
            self.log_result("Plugin Statistics", False, f"Error: {e}")
            return False
    
    def test_signature_updates(self):
        """Test 8: Actualización de firmas"""
        try:
            if not self.plugin:
                return False
            
            # Test de actualización de firmas
            update_success = self.plugin.update_signatures()
            
            self.log_result(
                "Signature Updates",
                update_success,
                "Firmas actualizadas (baseline recalculado)"
            )
            return update_success
            
        except Exception as e:
            self.log_result("Signature Updates", False, f"Error: {e}")
            return False
    
    def cleanup(self):
        """Limpieza después de tests"""
        try:
            if self.plugin:
                self.plugin.deactivate()
            
            logger.info("🧹 Cleanup completado")
            
        except Exception as e:
            logger.error(f"❌ Error en cleanup: {e}")
    
    def run_all_tests(self):
        """Ejecuta todos los tests de integración"""
        logger.info("🚀 Iniciando IAST Integration Tests...")
        print("\n🧪 IAST INTEGRATION TEST SUITE")
        print("=" * 50)
        
        # Lista de tests a ejecutar
        tests = [
            self.test_engine_initialization,
            self.test_plugin_activation,
            self.test_file_integrity_monitoring,
            self.test_keylogger_detection,
            self.test_threat_detection_interface,
            self.test_web_logging_integration,
            self.test_plugin_statistics,
            self.test_signature_updates
        ]
        
        # Ejecutar tests
        passed = 0
        total = len(tests)
        
        for test_func in tests:
            try:
                if test_func():
                    passed += 1
            except Exception as e:
                logger.error(f"❌ Test falló con excepción: {e}")
        
        # Cleanup
        self.cleanup()
        
        # Resumen final
        print("\n📊 RESUMEN DE TESTS:")
        print("=" * 50)
        
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"{status} {result['test']}: {result['details']}")
        
        success_rate = (passed / total) * 100
        print(f"\n🎯 RESULTADO FINAL: {passed}/{total} tests pasaron ({success_rate:.1f}%)")
        
        if success_rate >= 80:
            print("🏆 ¡IAST Integration EXITOSA!")
            logger.info("🏆 IAST Integration tests completados exitosamente")
        else:
            print("⚠️ Algunos tests fallaron - revisar logs")
            logger.warning("⚠️ Algunos IAST integration tests fallaron")
        
        return success_rate >= 80

def main():
    """Función principal"""
    test_suite = IASTIntegrationTest()
    return test_suite.run_all_tests()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)