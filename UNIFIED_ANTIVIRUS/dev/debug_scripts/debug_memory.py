#!/usr/bin/env python3
"""Debug Memory Analysis"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core import UnifiedAntivirusEngine

engine = UnifiedAntivirusEngine()

# Test casos de memoria
test_cases = [
    ("test.exe", 2048, 1024),  # ratio = 2.0
    ("process.exe", 1536, 1024),  # ratio = 1.5
    ("app.exe", 1024, 1024),  # ratio = 1.0
    ("normal.exe", 512, 1024)  # ratio = 0.5
]

for process_name, memory_mb, threshold_mb in test_cases:
    result = engine.analyze_memory_usage(process_name, memory_mb, threshold_mb)
    ratio = memory_mb / threshold_mb
    
    print(f"\n📊 {process_name}:")
    print(f"   Memory: {memory_mb}MB, Threshold: {threshold_mb}MB, Ratio: {ratio:.2f}")
    print(f"   Risk Level: {result['risk_level']}")
    print(f"   Suspicion Score: {result['suspicion_score']:.3f}")
    
    if result['risk_level'] == 'HIGH':
        expected_score = 0.5 + (ratio - 2.0) * 0.2
        print(f"   Expected Score: {min(0.9, expected_score):.3f}")