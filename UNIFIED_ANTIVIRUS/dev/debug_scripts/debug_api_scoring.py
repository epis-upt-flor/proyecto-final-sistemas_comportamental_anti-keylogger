#!/usr/bin/env python3
"""Debug script para API scoring tests"""

import sys
sys.path.append('.')
from plugins.detectors.keylogger_detector.keylogger_detector import KeyloggerDetector

# Test case 1: file logging
detector = KeyloggerDetector({})
result1 = detector.analyze_api_usage({
    'name': 'test.exe',
    'apis_called': ['CreateFileA', 'WriteFile', 'GetSystemTime']
})

print('Test 1 (file logging):')
print(f'  Suspicious: {result1["is_suspicious"]}')
print(f'  Score: {result1["risk_score"]}')
print(f'  Categories: {list(result1["details"]["api_categories"].keys())}')
print(f'  Breakdown: {result1["details"]["api_categories"]}')
print()

# Test case 2: mixed APIs
result2 = detector.analyze_api_usage({
    'name': 'mixed.exe', 
    'apis_called': ['SetWindowsHookEx', 'CreateWindow', 'WriteFile', 'ShowWindow']
})

print('Test 2 (mixed APIs):')
print(f'  Suspicious: {result2["is_suspicious"]}')
print(f'  Score: {result2["risk_score"]}')
print(f'  Categories: {list(result2["details"]["api_categories"].keys())}')
print(f'  Breakdown: {result2["details"]["api_categories"]}')