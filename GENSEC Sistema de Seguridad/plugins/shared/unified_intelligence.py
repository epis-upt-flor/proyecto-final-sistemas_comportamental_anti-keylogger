#!/usr/bin/env python3
"""
Unified Intelligence Engine
=========================

Sistema unificado de inteligencia para todos los detectores.
Reemplaza patrones "tontos" con análisis comportamental avanzado.
"""

import os
import json
import hashlib
import psutil
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
from datetime import datetime

class UnifiedIntelligenceEngine:
    """Motor de inteligencia unificado para todos los detectores"""
    
    def __init__(self):
        self.load_intelligence_data()
        
    def load_intelligence_data(self):
        """Carga datos de inteligencia avanzados"""
        
        # 🧠 PATRONES INTELIGENTES (no obvios)
        self.intelligent_patterns = {
            
            # Nombres que imitan procesos legítimos (técnica real)
            "process_masquerading": {
                "system_mimics": ["svchost", "csrss", "winlogon", "lsass", "explorer"],
                "browser_mimics": ["chrome", "firefox", "edge", "opera"],
                "security_mimics": ["windows defender", "avast", "norton", "kaspersky"],
                "generic_mimics": ["update", "service", "helper", "manager", "host"]
            },
            
            # Ubicaciones furtivas REALES
            "stealth_locations": {
                "high_stealth": [
                    "windows\\fonts",
                    "windows\\system32\\spool\\drivers", 
                    "programdata\\microsoft\\windows defender",
                    "users\\public\\documents\\shared",
                    "recycler"
                ],
                "medium_stealth": [
                    "appdata\\roaming\\microsoft\\windows\\start menu",
                    "programdata\\microsoft\\windows\\start menu",
                    "windows\\system32\\tasks",
                    "windows\\temp"
                ],
                "temp_abuse": [
                    "temp", "tmp", "temporary internet files",
                    "recent", "cookies", "history"
                ]
            },
            
            # Comportamientos sutiles REALES
            "behavioral_signatures": {
                "memory_patterns": {
                    "low_footprint": {"min_mb": 1, "max_mb": 50},
                    "thread_intensive": {"min_threads": 4, "cpu_threshold": 5},
                    "handle_hoarding": {"min_handles": 100}
                },
                "network_patterns": {
                    "data_bursts": {"min_interval": 300, "max_size": 1024},
                    "stealth_ports": [1337, 31337, 8080, 9999, 4444],
                    "beacon_intervals": [60, 300, 900, 1800, 3600]  # segundos
                },
                "file_patterns": {
                    "scattered_writes": True,
                    "temporary_staging": True, 
                    "encrypted_storage": True,
                    "log_fragmentation": True
                }
            },
            
            # APIs críticas (pero contextualizadas)
            "api_analysis": {
                "keyboard_hooks": [
                    "SetWindowsHookExA", "SetWindowsHookExW",
                    "CallNextHookEx", "UnhookWindowsHookEx"
                ],
                "input_monitoring": [
                    "GetAsyncKeyState", "GetKeyState", 
                    "RegisterRawInputDevices", "GetRawInputData"
                ],
                "window_management": [
                    "GetForegroundWindow", "GetWindowText",
                    "FindWindow", "EnumWindows"
                ],
                "process_manipulation": [
                    "CreateRemoteThread", "WriteProcessMemory",
                    "VirtualAllocEx", "SetWindowsHookEx"
                ]
            }
        }
        
        # 🛡️ WHITELIST INTELIGENTE EXPANDIDA
        self.expanded_whitelist = {
            "gaming_platforms": {
                "steam": ["steamwebhelper.exe", "steamerrorreporter.exe", "steamservice.exe"],
                "epic": ["epicwebhelper.exe", "epicgameslauncher.exe"],
                "origin": ["origin.exe", "originwebhelperservice.exe"],
                "battle_net": ["battle.net.exe", "blizzardupdate.exe"],
                "xbox": ["gamebar.exe", "gamebarui.exe"]
            },
            "development_tools": {
                "microsoft": ["code.exe", "devenv.exe", "msbuild.exe"],
                "jetbrains": ["idea64.exe", "pycharm64.exe", "webstorm64.exe"],
                "google": ["chrome.exe", "nacl64.exe"],
                "nodejs": ["node.exe", "npm.cmd"]
            },
            "system_utilities": {
                "browsers": ["firefox.exe", "msedge.exe", "opera.exe"],
                "media": ["vlc.exe", "spotify.exe", "discord.exe"],
                "productivity": ["notepad++.exe", "winrar.exe", "7z.exe"]
            }
        }
        
        # 🎯 CONTEXTOS DE AMENAZA
        self.threat_contexts = {
            "corporate_espionage": {
                "targets": ["outlook", "teams", "slack", "zoom"],
                "indicators": ["screenshot_intervals", "clipboard_monitoring"]
            },
            "credential_theft": {
                "targets": ["browsers", "password_managers", "vpn_clients"],
                "indicators": ["form_field_monitoring", "process_injection"]
            },
            "financial_fraud": {
                "targets": ["banking_apps", "crypto_wallets", "trading_platforms"],
                "indicators": ["transaction_monitoring", "session_hijacking"]
            }
        }
    
    def analyze_process_intelligence(self, process_info: Dict) -> Dict[str, float]:
        """Análisis inteligente unificado de procesos"""
        
        analysis = {
            "masquerading_score": 0.0,
            "stealth_location_score": 0.0, 
            "behavioral_score": 0.0,
            "api_abuse_score": 0.0,
            "whitelist_adjustment": 0.0,
            "context_relevance": 0.0
        }
        
        process_name = process_info.get('name', '').lower()
        exe_path = process_info.get('exe', '').lower()
        
        try:
            # 1. ANÁLISIS DE MASQUERADING
            analysis["masquerading_score"] = self._analyze_masquerading(process_name, exe_path)
            
            # 2. ANÁLISIS DE UBICACIÓN FURTIVA
            analysis["stealth_location_score"] = self._analyze_stealth_location(exe_path)
            
            # 3. ANÁLISIS BEHAVIORAL (requiere objeto proceso)
            if 'process_obj' in process_info:
                analysis["behavioral_score"] = self._analyze_behavioral_patterns(process_info['process_obj'])
            
            # 4. WHITELIST CHECK
            analysis["whitelist_adjustment"] = self._check_expanded_whitelist(process_name, exe_path)
            
            # 5. CONTEXTO DE AMENAZA
            analysis["context_relevance"] = self._analyze_threat_context(process_info)
            
        except Exception as e:
            print(f"Error en análisis inteligente: {e}")
        
        return analysis
    
    def _analyze_masquerading(self, process_name: str, exe_path: str) -> float:
        """Detecta procesos que imitan nombres legítimos"""
        score = 0.0
        
        # Verificar si imita proceso del sistema
        for system_name in self.intelligent_patterns["process_masquerading"]["system_mimics"]:
            if system_name in process_name:
                # Si tiene nombre de sistema pero NO está en ubicación de sistema
                if not any(sys_path in exe_path for sys_path in ["system32", "syswow64", "windows"]):
                    score += 0.8  # MUY sospechoso
                    break
        
        # Verificar imitación de navegadores
        for browser in self.intelligent_patterns["process_masquerading"]["browser_mimics"]:
            if browser in process_name:
                # Navegador fuera de ubicaciones típicas
                if not any(path in exe_path for path in ["program files", "google", "mozilla", "microsoft"]):
                    score += 0.6
                    break
        
        # Verificar nombres genéricos sospechosos
        generic_count = 0
        for generic in self.intelligent_patterns["process_masquerading"]["generic_mimics"]:
            if generic in process_name:
                generic_count += 1
        
        if generic_count > 0:
            score += min(generic_count * 0.3, 0.7)
        
        return min(score, 1.0)
    
    def _analyze_stealth_location(self, exe_path: str) -> float:
        """Analiza ubicaciones furtivas"""
        score = 0.0
        
        # Ubicaciones de alta furtividad
        for location in self.intelligent_patterns["stealth_locations"]["high_stealth"]:
            if location in exe_path:
                score += 0.8
                break
        
        # Ubicaciones de media furtividad
        for location in self.intelligent_patterns["stealth_locations"]["medium_stealth"]:
            if location in exe_path:
                score += 0.5
                break
        
        # Abuso de directorios temporales
        for temp_dir in self.intelligent_patterns["stealth_locations"]["temp_abuse"]:
            if temp_dir in exe_path:
                score += 0.4
                break
        
        return min(score, 1.0)
    
    def _analyze_behavioral_patterns(self, process) -> float:
        """Análisis de patrones comportamentales"""
        score = 0.0
        
        try:
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            # Patrón: Baja huella de memoria + múltiples threads
            mem_pattern = self.intelligent_patterns["behavioral_signatures"]["memory_patterns"]
            
            if (mem_pattern["low_footprint"]["min_mb"] <= memory_mb <= mem_pattern["low_footprint"]["max_mb"]):
                if process.num_threads() >= mem_pattern["thread_intensive"]["min_threads"]:
                    score += 0.6  # Típico de keyloggers
            
            # Patrón: CPU bajo pero muchos handles
            try:
                if hasattr(process, 'num_handles'):
                    if process.num_handles() > mem_pattern["handle_hoarding"]["min_handles"]:
                        if process.cpu_percent() < mem_pattern["thread_intensive"]["cpu_threshold"]:
                            score += 0.4
            except:
                pass
            
        except Exception:
            pass
        
        return min(score, 1.0)
    
    def _check_expanded_whitelist(self, process_name: str, exe_path: str) -> float:
        """Verificación expandida de whitelist"""
        adjustment = 0.0
        
        # Verificar por categorías
        for category, apps in self.expanded_whitelist.items():
            if isinstance(apps, dict):
                for subcategory, app_list in apps.items():
                    if any(app.lower() in process_name for app in app_list):
                        # Verificar ubicación legítima
                        if any(legit_path in exe_path for legit_path in ["program files", subcategory.lower()]):
                            adjustment = -0.7  # Reducir significativamente
                            return adjustment
        
        return adjustment
    
    def _analyze_threat_context(self, process_info: Dict) -> float:
        """Analiza contexto de amenaza específico"""
        score = 0.0
        
        # Por ahora retornamos 0, pero aquí se puede implementar
        # análisis específico de contexto según el entorno
        
        return score
    
    def calculate_unified_score(self, analysis: Dict[str, float]) -> Tuple[float, str]:
        """Calcula score unificado y determina tipo de amenaza"""
        
        # Pesos para cada componente
        weights = {
            "masquerading_score": 0.35,
            "stealth_location_score": 0.25, 
            "behavioral_score": 0.25,
            "api_abuse_score": 0.15
        }
        
        # Calcular score base
        base_score = sum(
            analysis.get(component, 0.0) * weight 
            for component, weight in weights.items()
        )
        
        # Aplicar ajuste de whitelist
        final_score = max(0.0, base_score + analysis.get("whitelist_adjustment", 0.0))
        
        # Determinar tipo de amenaza
        threat_type = "unknown"
        if final_score > 0.8:
            threat_type = "high_confidence_malware"
        elif final_score > 0.6:
            threat_type = "suspicious_behavior"
        elif final_score > 0.4:
            threat_type = "potentially_unwanted"
        else:
            threat_type = "likely_legitimate"
        
        return final_score, threat_type

def main():
    """Test del motor de inteligencia"""
    print("🧠 Testing Unified Intelligence Engine...")
    
    engine = UnifiedIntelligenceEngine()
    
    # Test con proceso sospechoso
    fake_svchost = {
        "name": "svchost.exe",
        "exe": "C:\\Users\\Public\\Documents\\svchost.exe",
        "cmdline": []
    }
    
    analysis = engine.analyze_process_intelligence(fake_svchost)
    score, threat_type = engine.calculate_unified_score(analysis)
    
    print(f"\nTest proceso falso (svchost.exe en Documents):")
    print(f"  Masquerading: {analysis['masquerading_score']:.2f}")
    print(f"  Stealth Location: {analysis['stealth_location_score']:.2f}")
    print(f"  Score Final: {score:.2f}")
    print(f"  Tipo de Amenaza: {threat_type}")
    
    # Test con proceso legítimo
    legit_steam = {
        "name": "steamwebhelper.exe",
        "exe": "C:\\Program Files (x86)\\Steam\\bin\\cef\\steamwebhelper.exe",
        "cmdline": []
    }
    
    analysis2 = engine.analyze_process_intelligence(legit_steam)
    score2, threat_type2 = engine.calculate_unified_score(analysis2)
    
    print(f"\nTest proceso legítimo (Steam):")
    print(f"  Masquerading: {analysis2['masquerading_score']:.2f}")
    print(f"  Whitelist Adjustment: {analysis2['whitelist_adjustment']:.2f}")
    print(f"  Score Final: {score2:.2f}")
    print(f"  Tipo de Amenaza: {threat_type2}")

if __name__ == "__main__":
    main()