#!/usr/bin/env python3
"""
Plugin Intelligence Upgrader
===========================

Actualiza TODOS los plugins detectores con inteligencia avanzada,
reemplazando patrones "tontos" con análisis comportamental.
"""

import os
import json
import shutil
from pathlib import Path
from typing import Dict, List

class PluginIntelligenceUpgrader:
    """Actualizador de inteligencia para todos los plugins"""
    
    def __init__(self, plugins_dir: str):
        self.plugins_dir = Path(plugins_dir)
        self.detectors_dir = self.plugins_dir / "detectors"
        self.backup_dir = self.plugins_dir / "backup_configs"
        
        # Crear directorio de backup
        self.backup_dir.mkdir(exist_ok=True)
        
    def analyze_all_plugins(self) -> Dict[str, Dict]:
        """Analiza todos los plugins para encontrar patrones tontos"""
        analysis = {}
        
        for detector_dir in self.detectors_dir.iterdir():
            if detector_dir.is_dir() and detector_dir.name != "generated":
                config_file = detector_dir / "config.json"
                if config_file.exists():
                    analysis[detector_dir.name] = self.analyze_plugin_config(config_file)
        
        return analysis
    
    def analyze_plugin_config(self, config_file: Path) -> Dict:
        """Analiza configuración de un plugin específico"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            issues = {
                "obvious_patterns": [],
                "naive_detections": [],
                "missing_whitelist": True,
                "intelligence_score": 0.0
            }
            
            # Buscar patrones obvios recursivamente
            self._find_obvious_patterns(config, issues["obvious_patterns"], "")
            
            # Calcular score de inteligencia
            issues["intelligence_score"] = self._calculate_intelligence_score(config, issues)
            
            return issues
            
        except Exception as e:
            return {"error": str(e)}
    
    def _find_obvious_patterns(self, obj, patterns_list: List, path: str):
        """Busca patrones obvios recursivamente en la configuración"""
        
        obvious_terms = [
            "keylog", "password", "stealer", "spyware", "spy", 
            "credentials", "stolen", "capture", "monitor",
            ".*keylog.*", ".*password.*", ".*stealer.*"
        ]
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                self._find_obvious_patterns(value, patterns_list, new_path)
                
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    # Verificar si el string contiene términos obvios
                    for term in obvious_terms:
                        if term.lower() in item.lower():
                            patterns_list.append({
                                "path": f"{path}[{i}]",
                                "value": item,
                                "issue": f"Obvious pattern: '{term}'"
                            })
                else:
                    self._find_obvious_patterns(item, patterns_list, f"{path}[{i}]")
    
    def _calculate_intelligence_score(self, config: Dict, issues: Dict) -> float:
        """Calcula score de inteligencia del plugin (0-10)"""
        score = 10.0  # Comenzar con puntuación perfecta
        
        # Penalizar patrones obvios
        obvious_count = len(issues["obvious_patterns"])
        score -= min(obvious_count * 0.5, 7.0)
        
        # Verificar si tiene whitelist
        has_whitelist = self._has_whitelist_logic(config)
        if not has_whitelist:
            score -= 1.5
        
        # Verificar análisis behavioral
        has_behavioral = self._has_behavioral_analysis(config)
        if not has_behavioral:
            score -= 1.0
        
        return max(0.0, score)
    
    def _has_whitelist_logic(self, config: Dict) -> bool:
        """Verifica si el plugin tiene lógica de whitelist"""
        # Buscar indicadores de whitelist
        whitelist_indicators = ["whitelist", "trusted", "legitimate", "exclude"]
        
        config_str = json.dumps(config).lower()
        return any(indicator in config_str for indicator in whitelist_indicators)
    
    def _has_behavioral_analysis(self, config: Dict) -> bool:
        """Verifica si tiene análisis comportamental avanzado"""
        behavioral_indicators = [
            "behavior", "pattern", "heuristic", "analysis",
            "memory", "thread", "cpu", "network"
        ]
        
        config_str = json.dumps(config).lower()
        return sum(1 for indicator in behavioral_indicators if indicator in config_str) >= 3
    
    def generate_upgrade_recommendations(self, analysis: Dict[str, Dict]) -> Dict:
        """Genera recomendaciones de actualización"""
        recommendations = {
            "critical_upgrades": [],
            "recommended_upgrades": [],
            "minor_improvements": []
        }
        
        for plugin_name, issues in analysis.items():
            if issues.get("intelligence_score", 0) < 4.0:
                recommendations["critical_upgrades"].append({
                    "plugin": plugin_name,
                    "score": issues.get("intelligence_score", 0),
                    "issues": issues.get("obvious_patterns", []),
                    "action": "Reemplazar completamente con sistema inteligente"
                })
            elif issues.get("intelligence_score", 0) < 7.0:
                recommendations["recommended_upgrades"].append({
                    "plugin": plugin_name,
                    "score": issues.get("intelligence_score", 0),
                    "action": "Mejorar patrones y agregar whitelist"
                })
            else:
                recommendations["minor_improvements"].append({
                    "plugin": plugin_name,
                    "score": issues.get("intelligence_score", 0),
                    "action": "Optimizaciones menores"
                })
        
        return recommendations
    
    def backup_configs(self):
        """Respalda todas las configuraciones actuales"""
        print("📦 Creando backup de configuraciones...")
        
        for detector_dir in self.detectors_dir.iterdir():
            if detector_dir.is_dir():
                config_file = detector_dir / "config.json"
                if config_file.exists():
                    backup_file = self.backup_dir / f"{detector_dir.name}_config_backup.json"
                    shutil.copy2(config_file, backup_file)
                    print(f"   ✅ {detector_dir.name} respaldado")
    
    def upgrade_behavior_detector(self):
        """Actualiza behavior_detector con inteligencia mejorada"""
        config_file = self.detectors_dir / "behavior_detector" / "config.json"
        
        if not config_file.exists():
            return False
        
        print("🔧 Actualizando Behavior Detector...")
        
        # Nueva configuración inteligente
        intelligent_config = {
            "plugin_info": {
                "name": "behavior_detector",
                "version": "2.0.0", 
                "description": "Detector comportamental INTELIGENTE - No obvio",
                "author": "Sistema Anti-Keylogger Unificado",
                "category": "detectors",
                "priority": 2
            },
            "behavior_config": {
                "risk_threshold": 0.7,
                "enable_whitelist": True,
                "enable_advanced_analysis": True,
                "enable_intelligence_engine": True,
                "analysis_timeout_ms": 10000,
                "use_unified_intelligence": True
            },
            "intelligent_detection": {
                "masquerading_detection": {
                    "enable": True,
                    "system_process_mimics": ["svchost", "csrss", "winlogon"],
                    "location_verification": True,
                    "weight": 0.35
                },
                "stealth_location_analysis": {
                    "enable": True,
                    "high_risk_locations": [
                        "windows\\fonts",
                        "windows\\system32\\spool\\drivers",
                        "recycler"
                    ],
                    "weight": 0.25
                },
                "behavioral_patterns": {
                    "memory_analysis": True,
                    "thread_analysis": True,
                    "handle_monitoring": True,
                    "network_behavior": True,
                    "weight": 0.25
                },
                "api_context_analysis": {
                    "contextualize_api_calls": True,
                    "legitimate_use_detection": True,
                    "weight": 0.15
                }
            },
            "whitelist": {
                "gaming_platforms": ["steam", "epic", "origin"],
                "development_tools": ["code.exe", "devenv.exe"],
                "browsers": ["chrome.exe", "firefox.exe", "edge.exe"],
                "trusted_publishers": ["Microsoft Corporation", "Google LLC", "Valve Corporation"]
            },
            "legacy_patterns_disabled": {
                "note": "Patrones obvios deshabilitados - usando inteligencia comportamental",
                "disabled_patterns": [
                    ".*keylog.*", ".*spyware.*", ".*stealer.*",
                    ".*passwords?.txt$", ".*credentials?.txt$"
                ]
            }
        }
        
        # Escribir nueva configuración
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(intelligent_config, f, indent=2, ensure_ascii=False)
        
        print("   ✅ Behavior Detector actualizado con inteligencia avanzada")
        return True
    
    def upgrade_keylogger_detector(self):
        """Actualiza keylogger_detector con inteligencia"""
        config_file = self.detectors_dir / "keylogger_detector" / "config.json"
        
        if not config_file.exists():
            return False
        
        print("🔧 Actualizando Keylogger Detector...")
        
        intelligent_config = {
            "plugin_info": {
                "name": "keylogger_detector",
                "version": "3.0.0",
                "description": "Detector especializado INTELIGENTE - Análisis comportamental",
                "author": "KrCrimson",
                "category": "detector", 
                "priority": "high"
            },
            "keylogger_detector": {
                "sensitivity": "high",
                "use_unified_intelligence": True,
                "behavioral_analysis": {
                    "process_masquerading": True,
                    "stealth_injection": True,
                    "memory_patterns": True,
                    "api_hooking_context": True
                },
                "detection_thresholds": {
                    "masquerading": 0.8,
                    "stealth_location": 0.7, 
                    "behavioral": 0.6,
                    "combined": 0.7
                },
                "intelligent_apis": {
                    "context_aware": True,
                    "legitimate_use_filter": True,
                    "hook_apis": ["SetWindowsHookEx", "CallNextHookEx"],
                    "input_apis": ["GetAsyncKeyState", "GetKeyState"],
                    "window_apis": ["GetForegroundWindow", "GetWindowText"]
                },
                "advanced_whitelist": {
                    "process_verification": True,
                    "location_verification": True,
                    "publisher_verification": True
                }
            },
            "legacy_detection_disabled": {
                "note": "Patrones de archivo obvios reemplazados por análisis comportamental",
                "old_patterns": [
                    ".*key.*log.*\\.txt$", ".*keystroke.*\\.(txt|log)$"
                ],
                "replacement": "Behavioral analysis + process intelligence"
            }
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(intelligent_config, f, indent=2, ensure_ascii=False)
        
        print("   ✅ Keylogger Detector actualizado")
        return True
    
    def generate_intelligence_report(self, analysis: Dict, recommendations: Dict) -> str:
        """Genera reporte completo de inteligencia"""
        
        report = []
        report.append("🧠 REPORTE DE INTELIGENCIA DE PLUGINS")
        report.append("=" * 50)
        report.append("")
        
        # Resumen general
        total_plugins = len(analysis)
        critical_count = len(recommendations["critical_upgrades"])
        report.append(f"📊 RESUMEN GENERAL:")
        report.append(f"   Total de plugins analizados: {total_plugins}")
        report.append(f"   Necesitan actualización crítica: {critical_count}")
        report.append("")
        
        # Análisis por plugin
        report.append("🔍 ANÁLISIS DETALLADO:")
        for plugin_name, issues in analysis.items():
            score = issues.get("intelligence_score", 0)
            obvious_count = len(issues.get("obvious_patterns", []))
            
            report.append(f"\n📋 {plugin_name.upper()}")
            report.append(f"   Score de Inteligencia: {score:.1f}/10.0")
            report.append(f"   Patrones obvios encontrados: {obvious_count}")
            
            if obvious_count > 0:
                report.append("   🚨 Problemas encontrados:")
                for pattern in issues["obvious_patterns"][:3]:  # Solo primeros 3
                    report.append(f"      - {pattern['issue']}: {pattern['value']}")
                if obvious_count > 3:
                    report.append(f"      - ... y {obvious_count - 3} más")
        
        # Recomendaciones
        report.append("\n🎯 RECOMENDACIONES:")
        
        if recommendations["critical_upgrades"]:
            report.append("\n❌ ACTUALIZACIONES CRÍTICAS NECESARIAS:")
            for upgrade in recommendations["critical_upgrades"]:
                report.append(f"   - {upgrade['plugin']}: {upgrade['action']}")
        
        if recommendations["recommended_upgrades"]:
            report.append("\n⚠️ ACTUALIZACIONES RECOMENDADAS:")
            for upgrade in recommendations["recommended_upgrades"]:
                report.append(f"   - {upgrade['plugin']}: {upgrade['action']}")
        
        report.append("\n✅ SIGUIENTE PASO:")
        report.append("   Ejecutar upgrade_all_plugins() para aplicar mejoras")
        
        return "\n".join(report)

def main():
    """Función principal - análisis completo del sistema"""
    
    plugins_dir = Path(__file__).parent  # Este archivo está en /plugins/
    upgrader = PluginIntelligenceUpgrader(plugins_dir)
    
    print("🔍 Analizando TODOS los plugins detectores...")
    analysis = upgrader.analyze_all_plugins()
    
    print("\n📊 Generando recomendaciones...")
    recommendations = upgrader.generate_upgrade_recommendations(analysis)
    
    print("\n📋 Generando reporte...")
    report = upgrader.generate_intelligence_report(analysis, recommendations)
    
    print("\n" + report)
    
    # Preguntar si aplicar upgrades
    print("\n" + "="*50)
    response = input("¿Aplicar actualizaciones inteligentes? (y/N): ")
    
    if response.lower() == 'y':
        print("\n🚀 Iniciando actualización inteligente...")
        
        # Backup
        upgrader.backup_configs()
        
        # Actualizar plugins críticos
        upgrader.upgrade_behavior_detector()
        upgrader.upgrade_keylogger_detector()
        
        print("\n🎉 ¡Actualización completada!")
        print("   Los plugins ahora usan inteligencia comportamental avanzada")
        print("   Backups guardados en: plugins/backup_configs/")

if __name__ == "__main__":
    main()