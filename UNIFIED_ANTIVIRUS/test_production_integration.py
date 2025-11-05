#!/usr/bin/env python3
"""
Test de Integración - Sistema Principal
=======================================

Test para verificar que MemoryMonitor y ConsensusEngine 
están correctamente integrados en el sistema principal.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import UnifiedAntivirusEngine


def test_integration():
    """Test de integración completa"""
    print("🔬 Iniciando test de integración...")
    
    # 1. Crear instancia del engine principal
    engine = UnifiedAntivirusEngine()
    print("✅ Engine principal creado")
    
    # 2. Verificar que tiene los componentes avanzados
    assert hasattr(engine, 'memory_monitor'), "Engine no tiene memory_monitor"
    assert hasattr(engine, 'consensus_engine'), "Engine no tiene consensus_engine"
    print("✅ Componentes avanzados presentes")
    
    # 3. Test MemoryMonitor integrado
    memory_result = engine.analyze_memory_usage("test.exe", 2048, 1024)
    assert memory_result["risk_level"] == "HIGH", f"Expected HIGH, got {memory_result['risk_level']}"
    assert memory_result["suspicion_score"] >= 0.8, f"Score too low: {memory_result['suspicion_score']}"
    print(f"✅ MemoryMonitor funcional: {memory_result['risk_level']}, score={memory_result['suspicion_score']:.2f}")
    
    # 4. Test ConsensusEngine integrado
    detector_results = {
        "ml_detector": {"risk_level": "HIGH", "confidence": 0.9, "score": 0.85},
        "behavior_detector": {"risk_level": "MEDIUM", "confidence": 0.7, "score": 0.65},
        "network_detector": {"risk_level": "HIGH", "confidence": 0.8, "score": 0.8}
    }
    consensus_result = engine.combine_threat_results(detector_results)
    assert consensus_result["final_risk_level"] == "HIGH", f"Expected HIGH, got {consensus_result['final_risk_level']}"
    print(f"✅ ConsensusEngine funcional: {consensus_result['final_risk_level']}, confidence={consensus_result['confidence']:.2f}")
    
    # 5. Verificar acceso directo a componentes
    memory_monitor = engine.get_memory_monitor()
    consensus_engine = engine.get_consensus_engine()
    assert memory_monitor is not None, "No se pudo obtener MemoryMonitor"
    assert consensus_engine is not None, "No se pudo obtener ConsensusEngine"
    print("✅ Acceso directo a componentes funcional")
    
    print("\n🎉 INTEGRACIÓN EXITOSA: Todos los componentes TDD están funcionando en producción")
    return True


if __name__ == "__main__":
    try:
        test_integration()
        print("\n✅ Sistema listo para producción con componentes TDD #7 y #8")
    except Exception as e:
        print(f"\n❌ Error en integración: {e}")
        sys.exit(1)