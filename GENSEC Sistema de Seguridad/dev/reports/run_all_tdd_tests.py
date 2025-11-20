#!/usr/bin/env python3
"""
Sistema de Testing TDD Completo - Reporte de Estado
==================================================

Ejecuta todos los tests TDD y genera un reporte de estado
del sistema anti-keylogger unificado.
"""

import sys
import subprocess
from pathlib import Path
import time

# Agregar directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

def run_test_suite(test_path, name):
    """Ejecuta un conjunto de tests TDD"""
    print(f"\n{'='*60}")
    print(f"🧪 EJECUTANDO: {name}")
    print(f"{'='*60}")
    
    cmd = f"set PYTHONPATH=%CD% && pytest {test_path} -v --tb=short"
    
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print(f"✅ {name}: TODOS LOS TESTS PASARON")
            # Contar tests pasados
            passed_count = result.stdout.count(" PASSED")
            print(f"   📊 Tests exitosos: {passed_count}")
            return True, passed_count, 0
        else:
            print(f"❌ {name}: ALGUNOS TESTS FALLARON")
            # Contar tests pasados y fallados
            passed_count = result.stdout.count(" PASSED")
            failed_count = result.stdout.count(" FAILED")
            print(f"   📊 Tests exitosos: {passed_count}")
            print(f"   📊 Tests fallados: {failed_count}")
            print(f"   🔍 Detalles de errores:")
            # Mostrar solo la línea de resumen
            lines = result.stdout.split('\n')
            for line in lines:
                if "FAILED" in line and "short test summary" not in line:
                    print(f"      - {line.strip()}")
            return False, passed_count, failed_count
            
    except Exception as e:
        print(f"❌ {name}: ERROR EN EJECUCIÓN - {e}")
        return False, 0, 1

def main():
    """Ejecuta todos los tests TDD del sistema"""
    print("🛡️ SISTEMA ANTI-KEYLOGGER UNIFICADO")
    print("📋 REPORTE COMPLETO DE TESTS TDD")
    print("=" * 60)
    
    start_time = time.time()
    
    # Lista de todos los tests TDD
    tdd_tests = [
        ("tests/tdd_01_api_hooking_detection/test_api_hooking_detection_tdd.py", "TDD #01 - API Hooking Detection"),
        ("tests/tdd_02_port_detection/test_port_detection_tdd.py", "TDD #02 - Port Detection"),
        ("tests/tdd_03_safe_process_validation/test_safe_process_validation_tdd.py", "TDD #03 - Safe Process Validation"),
        ("tests/tdd_04_cpu_monitoring/test_cpu_analysis.py", "TDD #04 - CPU Monitoring"),
        ("tests/tdd_05_detector_initialization/test_engine_init.py", "TDD #05 - Detector Initialization"),
        ("tests/tdd_06_feature_extraction/test_feature_extraction.py", "TDD #06 - Feature Extraction"),
        ("tests/tdd_07_consensus/test_consensus.py", "TDD #07 - Consensus Algorithm"),
        ("tests/tdd_08_memory_threshold/test_memory_threshold.py", "TDD #08 - Memory Threshold"),
    ]
    
    results = []
    total_passed = 0
    total_failed = 0
    
    # Ejecutar cada test suite
    for test_path, name in tdd_tests:
        success, passed, failed = run_test_suite(test_path, name)
        results.append((name, success, passed, failed))
        total_passed += passed
        total_failed += failed
    
    # Reporte final
    print(f"\n{'='*60}")
    print("📊 REPORTE FINAL - ESTADO DEL SISTEMA TDD")
    print(f"{'='*60}")
    
    success_count = sum(1 for _, success, _, _ in results if success)
    failure_count = len(results) - success_count
    
    print(f"🎯 Suites TDD exitosas: {success_count}/{len(results)}")
    print(f"📈 Tests individuales exitosos: {total_passed}")
    print(f"📉 Tests individuales fallados: {total_failed}")
    print(f"⏱️ Tiempo total: {time.time() - start_time:.2f}s")
    
    print(f"\n📋 DETALLE POR SUITE:")
    for name, success, passed, failed in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status} {name} ({passed}P/{failed}F)")
    
    # Estado general del sistema
    system_health = (total_passed / (total_passed + total_failed)) * 100 if (total_passed + total_failed) > 0 else 0
    
    print(f"\n🏥 SALUD DEL SISTEMA: {system_health:.1f}%")
    
    if system_health >= 95:
        print("🎉 SISTEMA LISTO PARA PRODUCCIÓN")
    elif system_health >= 80:
        print("⚠️ SISTEMA ESTABLE - Algunas mejoras necesarias")
    else:
        print("🚨 SISTEMA INESTABLE - Requiere atención inmediata")
    
    # Ejecutar test de integración final
    print(f"\n{'='*60}")
    print("🔧 TEST DE INTEGRACIÓN CON SISTEMA PRINCIPAL")
    print(f"{'='*60}")
    
    try:
        from core import UnifiedAntivirusEngine
        
        engine = UnifiedAntivirusEngine()
        
        # Test rápido de componentes integrados
        memory_result = engine.analyze_memory_usage("test.exe", 2048, 1024)
        consensus_result = engine.combine_threat_results({
            "ml_detector": {"risk_level": "HIGH", "confidence": 0.9, "score": 0.85},
            "behavior_detector": {"risk_level": "MEDIUM", "confidence": 0.7, "score": 0.65}
        })
        
        print("✅ MemoryMonitor integrado correctamente")
        print("✅ ConsensusEngine integrado correctamente")
        print("✅ Sistema principal funcional")
        
    except Exception as e:
        print(f"❌ Error en integración: {e}")
        return 1
    
    print(f"\n🎊 REPORTE COMPLETADO")
    print("Sistema anti-keylogger listo para uso en producción" if system_health >= 95 else 
          "Sistema requiere atención en componentes fallidos")
    
    return 0 if failure_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())