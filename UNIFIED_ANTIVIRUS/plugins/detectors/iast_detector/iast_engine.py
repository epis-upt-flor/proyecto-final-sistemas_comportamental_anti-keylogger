#!/usr/bin/env python3
"""
IAST Self-Protection & Keylogger Detection Engine
===============================================

Detector IAST especializado que:
1. Protege la integridad del propio antivirus
2. Detecta keyloggers usando análisis híbrido (SAST + DAST)
3. Solo genera logs, NO modifica código
"""

import os
import sys
import time
import psutil
import hashlib
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional

# Agregar el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from utils.logger import get_logger

# Import condicional para evitar problemas con relative imports
try:
    from .whitelist_manager import IASTWhitelistManager
except ImportError:
    from whitelist_manager import IASTWhitelistManager

class IASTSelfProtectionEngine:
    def __init__(self):
        self.logger = get_logger("iast_detector")
        
        # Archivos críticos del antivirus a proteger
        self.protected_paths = {
            "core/engine.py": None,
            "utils/logger.py": None,
            "plugins/detectors/ml_detector/ml_engine.py": None,
            "config/security_config.json": None,
            "config/unified_config.toml": None,
            "web_system/integration/web_log_handler.py": None
        }
        
        # Patrones INTELIGENTES de keyloggers (no obvios)
        self.keylogger_signatures = {
            # APIs críticas que SÍ usan keyloggers reales
            "critical_apis": [
                "SetWindowsHookExA", "SetWindowsHookExW",
                "GetAsyncKeyState", "GetKeyState", 
                "RegisterHotKey", "UnhookWindowsHookEx",
                "CallNextHookEx", "GetKeyboardState"
            ],
            # Ubicaciones furtivas REALES donde se esconden
            "stealth_locations": [
                "appdata\\roaming\\microsoft\\windows\\start menu",
                "programdata\\microsoft\\windows\\start menu",
                "users\\public\\documents",
                "windows\\system32\\spool\\drivers",
                "windows\\fonts",
                "temp",
                "recycler"
            ],
            # Comportamientos SUTILES reales
            "behavioral_patterns": [
                "multiple_threads_low_cpu",  # Threads para hooks pero CPU bajo
                "clipboard_monitoring",       # Acceso constante al clipboard
                "screenshot_intervals",       # Screenshots periódicos
                "network_burst_patterns",    # Envío de datos en ráfagas
                "process_injection",         # Inyección en procesos legítimos
                "memory_string_obfuscation"  # Strings ofuscados en memoria
            ],
            # Nombres CAMUFLADOS que usan crackers reales
            "stealth_names": [
                "svchost", "csrss", "winlogon", "lsass", "explorer",  # Procesos del sistema
                "update", "service", "helper", "manager", "host",      # Nombres genéricos
                "driver", "audio", "video", "graphics", "network",    # Servicios falsos
                "microsoft", "windows", "system", "security"          # Nombres legítimos
            ]
        }
        
        # Estado del monitor
        self.is_monitoring = False
        self.baseline_hashes = {}
        self.detected_threats = set()
        
        # Inicializar whitelist manager
        self.whitelist_manager = IASTWhitelistManager()
        
        # Inicializar baseline
        self.calculate_baseline_hashes()
        
    def calculate_baseline_hashes(self):
        """Calcula hashes iniciales de archivos protegidos"""
        try:
            antivirus_root = Path(__file__).parent.parent.parent.parent
            
            for file_path in self.protected_paths:
                full_path = antivirus_root / file_path
                if full_path.exists():
                    with open(full_path, 'rb') as f:
                        content = f.read()
                        file_hash = hashlib.sha256(content).hexdigest()
                        self.baseline_hashes[str(full_path)] = file_hash
                        self.logger.info(f"🔒 Baseline hash calculado para {file_path}")
            
            self.logger.info(f"✅ Baseline establecido para {len(self.baseline_hashes)} archivos")
            
        except Exception as e:
            self.logger.error(f"❌ Error calculando baseline: {e}")
    
    def check_file_integrity(self):
        """Verifica integridad de archivos críticos"""
        modifications_detected = []
        
        try:
            for file_path, baseline_hash in self.baseline_hashes.items():
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        current_content = f.read()
                        current_hash = hashlib.sha256(current_content).hexdigest()
                    
                    if current_hash != baseline_hash:
                        modifications_detected.append(file_path)
                        self.logger.warning(f"🚨 MODIFICACIÓN DETECTADA: {file_path}")
                        self.logger.warning(f"   Hash original: {baseline_hash[:16]}...")
                        self.logger.warning(f"   Hash actual:   {current_hash[:16]}...")
                        
                        # Actualizar baseline después de alertar
                        self.baseline_hashes[file_path] = current_hash
            
            if modifications_detected:
                self.log_security_event("ANTIVIRUS_INTEGRITY_COMPROMISED", {
                    "modified_files": modifications_detected,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "HIGH"
                })
            
            return len(modifications_detected) == 0
            
        except Exception as e:
            self.logger.error(f"❌ Error verificando integridad: {e}")
            return False
    
    def scan_for_keyloggers(self):
        """Escanea procesos en busca de keyloggers"""
        detected_keyloggers = []
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    process_info = process.info
                    
                    # Skip procesos del sistema
                    if not process_info['exe']:
                        continue
                    
                    # Análisis estático (SAST)
                    static_score = self.analyze_process_static(process_info)
                    
                    # Análisis dinámico (DAST) 
                    dynamic_score = self.analyze_process_dynamic(process)
                    
                    # Análisis de comportamiento avanzado
                    advanced_score = self.analyze_advanced_behavior(process)
                    
                    # IAST: Combinación inteligente de scores
                    raw_score = (static_score * 0.4) + (dynamic_score * 0.35) + (advanced_score * 0.25)
                    
                    # 🧠 APLICAR WHITELIST INTELIGENTE
                    whitelist_result = self.whitelist_manager.is_whitelisted(
                        process_info['name'], 
                        process_info['exe'], 
                        process_info.get('cmdline', [])
                    )
                    
                    # Ajustar score basado en whitelist
                    total_score = max(0.0, raw_score + whitelist_result['confidence_adjustment'])
                    
                    # Log de whitelist si aplica
                    if whitelist_result['confidence_adjustment'] < 0:
                        self.logger.debug(f"🛡️ Whitelist aplicada a {process_info['name']}: {whitelist_result['whitelist_reason']}")
                        self.logger.debug(f"   Score ajustado: {raw_score:.2f} → {total_score:.2f}")
                    
                    if total_score > 0.7:  # Threshold de detección
                        keylogger_info = {
                            "pid": process_info['pid'],
                            "name": process_info['name'],
                            "exe": process_info['exe'],
                            "cmdline": process_info['cmdline'],
                            "static_score": static_score,
                            "dynamic_score": dynamic_score,
                            "advanced_score": advanced_score,
                            "raw_score": raw_score,
                            "total_score": total_score,
                            "whitelist_applied": whitelist_result['confidence_adjustment'] < 0,
                            "trust_level": whitelist_result['trust_level'],
                            "detection_type": "intelligent_behavioral_analysis",
                            "detection_time": datetime.now().isoformat()
                        }
                        
                        detected_keyloggers.append(keylogger_info)
                        self.detected_threats.add(process_info['pid'])
                        
                        self.logger.error(f"🎯 KEYLOGGER DETECTADO: {process_info['name']} (PID: {process_info['pid']})")
                        self.logger.error(f"   Score total: {total_score:.2f} (SAST: {static_score:.2f}, DAST: {dynamic_score:.2f}, Advanced: {advanced_score:.2f})")
                        self.logger.error(f"   Tipo de detección: Análisis comportamental inteligente")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if detected_keyloggers:
                self.log_security_event("KEYLOGGER_DETECTION", {
                    "detected_count": len(detected_keyloggers),
                    "keyloggers": detected_keyloggers,
                    "severity": "CRITICAL"
                })
            
            return detected_keyloggers
            
        except Exception as e:
            self.logger.error(f"❌ Error escaneando keyloggers: {e}")
            return []
    
    def analyze_process_static(self, process_info: Dict) -> float:
        """Análisis estático INTELIGENTE del proceso (SAST)"""
        score = 0.0
        
        try:
            exe_path = process_info.get('exe', '').lower()
            process_name = process_info.get('name', '').lower()
            cmdline = ' '.join(process_info.get('cmdline', [])).lower()
            
            # ⚠️ DETECCIÓN INTELIGENTE: Procesos con nombres de sistema pero ubicaciones raras
            system_names = self.keylogger_signatures['stealth_names']
            for sys_name in system_names:
                if sys_name in process_name:
                    # Si tiene nombre de sistema pero NO está en System32/SysWOW64
                    if 'system32' not in exe_path and 'syswow64' not in exe_path and 'windows' not in exe_path:
                        score += 0.6  # MUY sospechoso - proceso falso
                        self.logger.debug(f"� Proceso sistema falso: {process_name} en {exe_path}")
            
            # 🎯 Ubicaciones furtivas REALES
            for stealth_loc in self.keylogger_signatures['stealth_locations']:
                if stealth_loc in exe_path:
                    score += 0.4
                    self.logger.debug(f"🕵️ Ubicación furtiva: {stealth_loc}")
            
            # 🔍 Análisis de entropía del nombre (nombres generados aleatoriamente)
            if self._has_suspicious_entropy(process_name):
                score += 0.3
                self.logger.debug(f"🎲 Entropía sospechosa en nombre: {process_name}")
            
            # 📝 Línea de comandos minimalista (keyloggers evitan parámetros obviosos)
            if len(cmdline.split()) <= 1 and exe_path:  # Solo ejecutable, sin parámetros
                score += 0.2  # Sospechoso - la mayoría de apps legítimas tienen parámetros
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.debug(f"Error en análisis estático: {e}")
            return 0.0
    
    def _has_suspicious_entropy(self, name: str) -> bool:
        """Detecta nombres con entropía alta (generados aleatoriamente)"""
        if len(name) < 4:
            return False
        
        # Contar caracteres únicos vs longitud
        unique_chars = len(set(name.lower()))
        total_chars = len(name)
        entropy_ratio = unique_chars / total_chars
        
        # Nombres aleatorios tienen alta entropía (muchos caracteres únicos)
        # Nombres normales tienen patrones (explorer, chrome, etc.)
        return entropy_ratio > 0.7 and len(name) > 6
    
    def analyze_process_dynamic(self, process) -> float:
        """Análisis dinámico AVANZADO del proceso (DAST)"""
        score = 0.0
        
        try:
            # 🎯 PATRÓN REAL: CPU bajo + alta actividad de threads (hooks)
            cpu_percent = process.cpu_percent()
            num_threads = process.num_threads()
            
            # Keyloggers reales: bajo CPU pero múltiples threads para hooks
            if 0.1 <= cpu_percent <= 3.0 and num_threads >= 4:
                score += 0.4  # Muy característico
                self.logger.debug(f"🕵️ Patrón keylogger: CPU {cpu_percent}%, {num_threads} threads")
            
            # 🌐 Conexiones sospechosas INTELIGENTES
            try:
                connections = process.connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        # Conexiones a puertos no estándar (no 80, 443, 25, etc.)
                        if hasattr(conn, 'raddr') and conn.raddr:
                            port = conn.raddr.port
                            if port not in [80, 443, 25, 110, 143, 993, 995, 587]:
                                score += 0.5  # Puerto raro = muy sospechoso
                                self.logger.debug(f"🌐 Conexión a puerto inusual: {port}")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # 📁 ANÁLISIS INTELIGENTE de archivos
            try:
                open_files = process.open_files()
                
                # Buscar patrones reales de keyloggers
                for file_obj in open_files:
                    file_path = file_obj.path.lower()
                    
                    # Archivos en ubicaciones temporales + nombres random
                    if ('temp' in file_path or 'tmp' in file_path) and self._is_random_filename(file_path):
                        score += 0.3
                        
                    # Múltiples archivos pequeños (logs fragmentados)
                    if file_path.endswith(('.dat', '.tmp', '.log')) and 'windows' not in file_path:
                        score += 0.2
                        
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # 🔒 Detección de inyección en procesos legítimos
            try:
                # Si el proceso tiene el mismo nombre que uno legítimo pero PID diferente
                process_name = process.name().lower()
                if process_name in ['explorer.exe', 'svchost.exe', 'csrss.exe']:
                    # Verificar si hay múltiples instancias con comportamiento diferente
                    similar_processes = [p for p in psutil.process_iter() if p.name().lower() == process_name]
                    if len(similar_processes) > 1:
                        score += 0.3  # Posible inyección o proceso falso
                        
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.debug(f"Error en análisis dinámico: {e}")
            return 0.0
    
    def _is_random_filename(self, filepath: str) -> bool:
        """Detecta nombres de archivo generados aleatoriamente"""
        filename = os.path.basename(filepath).lower()
        
        # Remover extensión
        name_without_ext = os.path.splitext(filename)[0]
        
        if len(name_without_ext) < 4:
            return False
        
        # Características de nombres aleatorios:
        # 1. Muchos números mezclados con letras
        # 2. Falta de palabras reconocibles
        # 3. Patrones hexadecimales
        
        digit_count = sum(1 for c in name_without_ext if c.isdigit())
        alpha_count = sum(1 for c in name_without_ext if c.isalpha())
        
        # Si más del 40% son números mezclados = sospechoso
        if digit_count > 0 and (digit_count / len(name_without_ext)) > 0.4:
            return True
            
        # Patrones hex comunes (8-16 caracteres hex)
        if len(name_without_ext) >= 8 and all(c in '0123456789abcdef' for c in name_without_ext):
            return True
            
        return False
    
    def analyze_advanced_behavior(self, process) -> float:
        """Análisis de comportamiento avanzado - APIs y memoria"""
        score = 0.0
        
        try:
            # 🧠 Análisis de memoria avanzado
            memory_info = process.memory_info()
            
            # Keyloggers reales usan poca memoria pero de manera constante
            if memory_info.rss < 50 * 1024 * 1024:  # Menos de 50MB
                if process.num_threads() > 3:  # Pero múltiples threads
                    score += 0.3
                    self.logger.debug(f"🧠 Patrón memoria: {memory_info.rss/1024/1024:.1f}MB con {process.num_threads()} threads")
            
            # 🔍 Análisis de handles (keyloggers mantienen muchos handles abiertos)
            try:
                # En Windows, los keyloggers mantienen handles a ventanas y hooks
                if hasattr(process, 'num_handles'):
                    handles = process.num_handles()
                    if handles > 100:  # Muchos handles = posible monitoreo
                        score += 0.2
                        
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # ⏱️ Análisis temporal - procesos que llevan tiempo corriendo
            try:
                create_time = datetime.fromtimestamp(process.create_time())
                uptime = datetime.now() - create_time
                
                # Keyloggers suelen ejecutarse por largos períodos
                if uptime.total_seconds() > 3600:  # Más de 1 hora
                    current_cpu = process.cpu_percent()
                    if current_cpu < 5:  # Con bajo CPU
                        score += 0.2
                        
            except (psutil.AccessDenied, OSError):
                pass
            
            # 🎯 Detección de patrones de acceso a ventanas
            try:
                # Si el proceso no tiene ventana visible pero tiene threads UI
                if not self._has_visible_window(process) and process.num_threads() > 2:
                    score += 0.3
                    self.logger.debug(f"👻 Proceso sin ventana con múltiples threads: {process.name()}")
                    
            except Exception:
                pass
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.debug(f"Error en análisis avanzado: {e}")
            return 0.0
    
    def _has_visible_window(self, process) -> bool:
        """Detecta si el proceso tiene ventanas visibles (Windows API simulation)"""
        try:
            # Simulación simple - procesos con GUI normalmente tienen más memoria
            memory_mb = process.memory_info().rss / 1024 / 1024
            
            # Procesos GUI típicamente usan más de 20MB
            # Procesos en background/keyloggers usan menos
            return memory_mb > 20
            
        except Exception:
            return False
    
    def log_security_event(self, event_type: str, details: Dict):
        """Registra eventos de seguridad"""
        try:
            event_data = {
                "event_type": event_type,
                "timestamp": datetime.now().isoformat(),
                "details": details,
                "source": "IAST_Engine"
            }
            
            # Log estructurado para el sistema web
            self.logger.error(f"🚨 EVENTO DE SEGURIDAD: {event_type}")
            self.logger.error(f"📊 Detalles: {details}")
            
            # Aquí podrías enviar también a un sistema de alertas externo
            # self.send_alert_to_security_team(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Error registrando evento de seguridad: {e}")
    
    def start_monitoring(self, interval: int = 30):
        """Inicia el monitoreo continuo"""
        if self.is_monitoring:
            self.logger.warning("⚠️ El monitoreo IAST ya está activo")
            return
        
        self.is_monitoring = True
        self.logger.info("🚀 Iniciando monitoreo IAST...")
        
        def monitoring_loop():
            while self.is_monitoring:
                try:
                    # Verificar integridad del antivirus
                    integrity_ok = self.check_file_integrity()
                    
                    # Escanear keyloggers
                    detected = self.scan_for_keyloggers()
                    
                    # Log de estado
                    if integrity_ok and len(detected) == 0:
                        self.logger.debug("✅ Sistema seguro - Sin amenazas detectadas")
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    self.logger.error(f"❌ Error en bucle de monitoreo: {e}")
                    time.sleep(5)  # Pausa corta antes de reintentar
        
        # Ejecutar en thread separado
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        
        self.logger.info(f"✅ Monitoreo IAST iniciado (intervalo: {interval}s)")
    
    def stop_monitoring(self):
        """Detiene el monitoreo"""
        self.is_monitoring = False
        self.logger.info("🛑 Monitoreo IAST detenido")
    
    def get_detection_report(self) -> Dict:
        """Genera reporte de detecciones"""
        return {
            "monitoring_active": self.is_monitoring,
            "protected_files": len(self.baseline_hashes),
            "detected_threats": len(self.detected_threats),
            "last_scan": datetime.now().isoformat(),
            "threat_pids": list(self.detected_threats)
        }

def main():
    """Función principal para testing"""
    print("🔧 Inicializando IAST Self-Protection Engine...")
    
    engine = IASTSelfProtectionEngine()
    
    # Test de integridad
    print("\n1. Verificando integridad del antivirus...")
    integrity_ok = engine.check_file_integrity()
    print(f"   Resultado: {'✅ OK' if integrity_ok else '❌ COMPROMETIDO'}")
    
    # Test de detección de keyloggers
    print("\n2. Escaneando keyloggers...")
    detected = engine.scan_for_keyloggers()
    print(f"   Keyloggers detectados: {len(detected)}")
    
    # Reporte final
    print("\n3. Reporte de estado:")
    report = engine.get_detection_report()
    for key, value in report.items():
        print(f"   {key}: {value}")

if __name__ == "__main__":
    main()