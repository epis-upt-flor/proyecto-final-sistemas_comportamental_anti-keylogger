#!/usr/bin/env python3
"""Debug Consensus Engine"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core import UnifiedAntivirusEngine

engine = UnifiedAntivirusEngine()

# Datos del test 
detector_results = {
    "ml_detector": {"risk_level": "HIGH", "confidence": 0.9, "score": 0.85},
    "behavior_detector": {"risk_level": "MEDIUM", "confidence": 0.7, "score": 0.65},
    "network_detector": {"risk_level": "HIGH", "confidence": 0.8, "score": 0.8}
}

print("🔍 Debug Consensus Engine:")
print(f"Input: {detector_results}")

result = engine.combine_threat_results(detector_results)

print(f"\nResultado: {result}")
print(f"Final Risk Level: {result['final_risk_level']}")
print(f"Consensus Score: {result['consensus_score']:.3f}")
print(f"Confidence: {result['confidence']:.3f}")

# Calcular manualmente para verificar
consensus_engine = engine.get_consensus_engine()
weights = consensus_engine.detector_weights
risk_values = consensus_engine.risk_values

print(f"\n📊 Cálculo manual:")
print(f"Weights: {weights}")
print(f"Risk Values: {risk_values}")

total_weighted_score = 0.0
total_weight = 0.0
total_confidence = 0.0

for detector_name, result_data in detector_results.items():
    weight = weights.get(detector_name, 0.1)
    confidence = result_data['confidence']
    score = result_data['score']
    
    weighted_score = score * confidence * weight
    total_weighted_score += weighted_score
    total_weight += weight
    total_confidence += confidence
    
    print(f"  {detector_name}: weight={weight}, confidence={confidence}, score={score}")
    print(f"    -> weighted_score = {score} * {confidence} * {weight} = {weighted_score:.3f}")

final_score = total_weighted_score / total_weight
avg_confidence = total_confidence / len(detector_results)

print(f"\nTotal weighted score: {total_weighted_score:.3f}")
print(f"Total weight: {total_weight:.3f}")
print(f"Final consensus score: {final_score:.3f}")
print(f"Avg confidence: {avg_confidence:.3f}")

if final_score >= 0.8:
    expected_level = "HIGH"
elif final_score >= 0.6:
    expected_level = "MEDIUM"
elif final_score >= 0.3:
    expected_level = "LOW"
else:
    expected_level = "NORMAL"

print(f"Expected level (score {final_score:.3f}): {expected_level}")