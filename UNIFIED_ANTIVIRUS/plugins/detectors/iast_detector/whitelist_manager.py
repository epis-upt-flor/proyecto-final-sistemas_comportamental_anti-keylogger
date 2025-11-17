#!/usr/bin/env python3
"""
IAST Whitelist Manager
====================

Sistema inteligente de whitelist para reducir falsos positivos.
Mantiene listas de procesos legítimos que pueden parecer sospechosos.
"""

import os
import json
from typing import Dict, List, Set
from pathlib import Path

class IASTWhitelistManager:
    """Administrador inteligente de whitelist para IAST"""
    
    def __init__(self):
        self.legitimate_processes = self._load_legitimate_processes()
        self.trusted_publishers = self._load_trusted_publishers()
        self.known_locations = self._load_known_locations()
    
    def _load_legitimate_processes(self) -> Dict[str, Dict]:
        """Carga procesos legítimos conocidos que pueden dar falsos positivos"""
        return {
            # Gaming platforms
            "steamwebhelper.exe": {
                "publisher": "Valve Corporation",
                "legitimate_paths": ["steam\\bin\\cef", "program files (x86)\\steam"],
                "reason": "Steam browser helper - múltiples instancias normales",
                "expected_behavior": ["multiple_instances", "network_activity", "low_cpu"]
            },
            "epicwebhelper.exe": {
                "publisher": "Epic Games",
                "legitimate_paths": ["epic games\\launcher", "program files\\epic"],
                "reason": "Epic Games browser helper",
                "expected_behavior": ["network_activity", "multiple_threads"]
            },
            
            # Browsers and web helpers
            "msedgewebview2.exe": {
                "publisher": "Microsoft Corporation",
                "legitimate_paths": ["microsoft\\edge", "program files"],
                "reason": "Microsoft Edge WebView2 runtime",
                "expected_behavior": ["multiple_instances", "memory_intensive"]
            },
            "chrome.exe": {
                "publisher": "Google LLC", 
                "legitimate_paths": ["google\\chrome", "program files"],
                "reason": "Google Chrome browser",
                "expected_behavior": ["multiple_processes", "high_memory"]
            },
            
            # Development tools
            "code.exe": {
                "publisher": "Microsoft Corporation",
                "legitimate_paths": ["microsoft vs code", "programs\\microsoft"],
                "reason": "Visual Studio Code editor",
                "expected_behavior": ["multiple_instances", "file_monitoring"]
            },
            "python.exe": {
                "publisher": "Python Software Foundation",
                "legitimate_paths": ["python", "appdata\\local\\programs\\python"],
                "reason": "Python interpreter",
                "expected_behavior": ["variable_behavior", "script_execution"]
            },
            
            # System utilities
            "discord.exe": {
                "publisher": "Discord Inc.",
                "legitimate_paths": ["discord", "appdata\\local\\discord"],
                "reason": "Discord communication client",
                "expected_behavior": ["network_activity", "background_running"]
            },
            "opera.exe": {
                "publisher": "Opera Software",
                "legitimate_paths": ["opera", "program files"],
                "reason": "Opera browser",
                "expected_behavior": ["multiple_processes", "network_intensive"]
            }
        }
    
    def _load_trusted_publishers(self) -> Set[str]:
        """Publishers confiables que reducen probabilidad de malware"""
        return {
            "Microsoft Corporation",
            "Google LLC",
            "Mozilla Corporation",
            "Valve Corporation", 
            "Epic Games",
            "Discord Inc.",
            "Opera Software",
            "Adobe Inc.",
            "NVIDIA Corporation",
            "Intel Corporation",
            "AMD Inc."
        }
    
    def _load_known_locations(self) -> Dict[str, str]:
        """Ubicaciones conocidas y su nivel de confianza"""
        return {
            "program files": "high_trust",
            "program files (x86)": "high_trust", 
            "windows\\system32": "system_trust",
            "windows\\syswow64": "system_trust",
            "microsoft\\edge": "trusted_app",
            "google\\chrome": "trusted_app",
            "steam": "gaming_platform",
            "epic games": "gaming_platform",
            "discord": "communication_app",
            "temp": "low_trust",
            "appdata\\roaming": "medium_trust",
            "appdata\\local": "medium_trust"
        }
    
    def is_whitelisted(self, process_name: str, exe_path: str, cmdline: List[str]) -> Dict[str, any]:
        """
        Verifica si un proceso está en whitelist y calcula ajuste de score
        
        Returns:
            Dict con información de whitelist y ajuste de score
        """
        result = {
            "is_whitelisted": False,
            "confidence_adjustment": 0.0,
            "whitelist_reason": "",
            "trust_level": "unknown"
        }
        
        process_name_lower = process_name.lower()
        exe_path_lower = exe_path.lower()
        
        # Verificar si está en procesos legítimos conocidos
        if process_name_lower in self.legitimate_processes:
            process_info = self.legitimate_processes[process_name_lower]
            
            # Verificar ubicación legítima
            is_legitimate_location = any(
                path in exe_path_lower for path in process_info["legitimate_paths"]
            )
            
            if is_legitimate_location:
                result["is_whitelisted"] = True
                result["confidence_adjustment"] = -0.6  # Reducir score significativamente
                result["whitelist_reason"] = process_info["reason"]
                result["trust_level"] = "known_legitimate"
                return result
        
        # Verificar ubicación de confianza
        trust_score = self._calculate_location_trust(exe_path_lower)
        if trust_score > 0:
            result["confidence_adjustment"] = -trust_score
            result["trust_level"] = "trusted_location"
            result["whitelist_reason"] = f"Ubicación confiable: {exe_path}"
        
        # Análisis de firma digital (simulado)
        publisher_trust = self._analyze_publisher_trust(exe_path, cmdline)
        if publisher_trust > 0:
            result["confidence_adjustment"] += -publisher_trust
            result["trust_level"] = "trusted_publisher"
            
        return result
    
    def _calculate_location_trust(self, exe_path: str) -> float:
        """Calcula score de confianza basado en ubicación"""
        trust_reduction = 0.0
        
        for location, trust_level in self.known_locations.items():
            if location in exe_path:
                if trust_level == "high_trust":
                    trust_reduction = max(trust_reduction, 0.5)
                elif trust_level == "system_trust":
                    trust_reduction = max(trust_reduction, 0.7)
                elif trust_level == "trusted_app":
                    trust_reduction = max(trust_reduction, 0.4)
                elif trust_level == "gaming_platform":
                    trust_reduction = max(trust_reduction, 0.3)
                elif trust_level == "medium_trust":
                    trust_reduction = max(trust_reduction, 0.2)
                    
        return trust_reduction
    
    def _analyze_publisher_trust(self, exe_path: str, cmdline: List[str]) -> float:
        """Analiza confiabilidad del publisher (simulado)"""
        # En implementación real, esto verificaría firmas digitales
        # Por ahora, simulamos basado en rutas conocidas
        
        publisher_indicators = {
            "microsoft": 0.4,
            "google": 0.3, 
            "steam": 0.3,
            "valve": 0.3,
            "discord": 0.2,
            "opera": 0.2
        }
        
        trust_score = 0.0
        for indicator, score in publisher_indicators.items():
            if indicator in exe_path.lower():
                trust_score = max(trust_score, score)
                
        return trust_score
    
    def add_to_whitelist(self, process_name: str, exe_path: str, reason: str):
        """Añade proceso a whitelist dinámica"""
        # En implementación real, esto persistiría en base de datos
        self.legitimate_processes[process_name.lower()] = {
            "legitimate_paths": [os.path.dirname(exe_path).lower()],
            "reason": f"Añadido manualmente: {reason}",
            "expected_behavior": ["user_defined"]
        }
    
    def get_whitelist_stats(self) -> Dict[str, int]:
        """Obtiene estadísticas de whitelist"""
        return {
            "known_processes": len(self.legitimate_processes),
            "trusted_publishers": len(self.trusted_publishers),
            "known_locations": len(self.known_locations)
        }

def main():
    """Test del whitelist manager"""
    print("🧪 Testing IAST Whitelist Manager...")
    
    wl_manager = IASTWhitelistManager()
    
    # Test con steamwebhelper (debería estar whitelisted)
    result = wl_manager.is_whitelisted(
        "steamwebhelper.exe",
        "C:\\Program Files (x86)\\Steam\\bin\\cef\\cef.win7x64\\steamwebhelper.exe",
        []
    )
    
    print(f"Test SteamWebHelper:")
    print(f"  Whitelisted: {result['is_whitelisted']}")
    print(f"  Ajuste de score: {result['confidence_adjustment']}")
    print(f"  Razón: {result['whitelist_reason']}")
    print(f"  Nivel de confianza: {result['trust_level']}")
    
    # Stats
    stats = wl_manager.get_whitelist_stats()
    print(f"\nEstadísticas:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()