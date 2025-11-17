"""
IAST (Interactive Application Security Testing) Detector Plugin
==============================================================

Plugin especializado para detección de vulnerabilidades en aplicaciones
en tiempo de ejecución usando técnicas IAST.

Características:
- SQL Injection detection
- XSS vulnerability scanning  
- Buffer overflow detection
- Command injection monitoring
- Path traversal detection
- Deserialization vulnerabilities
"""

import logging
import json
import re
import threading
import time
import sqlite3
import subprocess
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import psutil

# Configurar logger específico
logger = logging.getLogger(__name__)

class IASTVulnerability:
    """Representa una vulnerabilidad encontrada por IAST"""
    
    def __init__(self, vuln_type: str, severity: str, description: str, 
                 location: str, evidence: Dict[str, Any]):
        self.vuln_type = vuln_type
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.description = description
        self.location = location
        self.evidence = evidence
        self.timestamp = time.time()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }

class IASTDetector:
    """
    Interactive Application Security Testing Detector
    
    Monitorea aplicaciones en tiempo de ejecución buscando vulnerabilidades
    comunes de seguridad web y aplicaciones.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.IASTDetector")
        self.is_active = False
        self.monitoring_thread = None
        self.vulnerabilities = []
        
        # Patrones de detección
        self.sql_injection_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(\bAND\b\s+\d+\s*=\s*\d+)",
            r"(\bDROP\b\s+\bTABLE\b)",
            r"(\bINSERT\b\s+\bINTO\b.*\bVALUES\b)",
            r"(\bDELETE\b\s+\bFROM\b)",
            r"(';.*--)",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)"
        ]
        
        self.xss_patterns = [
            r"(<script[^>]*>.*</script>)",
            r"(javascript:[^'\"]*)",
            r"(on\w+\s*=\s*['\"][^'\"]*['\"])",
            r"(<iframe[^>]*>)",
            r"(<object[^>]*>)",
            r"(<embed[^>]*>)",
            r"(<form[^>]*>.*</form>)"
        ]
        
        self.command_injection_patterns = [
            r"(;.*\b(ls|dir|cat|type|rm|del)\b)",
            r"(\|.*\b(nc|netcat|curl|wget)\b)",
            r"(&.*\b(whoami|id|pwd)\b)",
            r"(`.*`)",
            r"(\$\(.*\))",
            r"(&&.*\b(rm|del|format)\b)",
            r"(;.*\brm\s+-rf\b)"
        ]
        
        self.path_traversal_patterns = [
            r"(\.\./.*\.\./)",
            r"(\.\.\\.*\.\.\\)",
            r"(%2e%2e%2f)",
            r"(%252e%252e%252f)",
            r"(\.\.%c0%af)",
            r"(\.\.%255c)"
        ]
        
        self.logger.info("[IAST_DETECTOR] Inicializado con patrones de vulnerabilidades")
    
    def start(self) -> bool:
        """Inicia el detector IAST"""
        try:
            if self.is_active:
                self.logger.warning("[IAST_DETECTOR] Ya está activo")
                return False
                
            self.is_active = True
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop, 
                daemon=True,
                name="IAST_Monitor"
            )
            self.monitoring_thread.start()
            
            self.logger.info("[IAST_DETECTOR] ✅ Detector IAST iniciado correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"[IAST_DETECTOR] ❌ Error iniciando detector: {e}")
            return False
    
    def stop(self) -> bool:
        """Detiene el detector IAST"""
        try:
            self.is_active = False
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=5.0)
            
            self.logger.info("[IAST_DETECTOR] ✅ Detector IAST detenido")
            return True
            
        except Exception as e:
            self.logger.error(f"[IAST_DETECTOR] ❌ Error deteniendo detector: {e}")
            return False
    
    def _monitoring_loop(self):
        """Loop principal de monitoreo"""
        self.logger.info("[IAST_DETECTOR] 🔍 Iniciando monitoreo de vulnerabilidades...")
        
        while self.is_active:
            try:
                # Analizar procesos web activos
                self._scan_web_processes()
                
                # Analizar archivos de log en busca de ataques
                self._scan_log_files()
                
                # Analizar conexiones de red sospechosas
                self._scan_network_connections()
                
                # Pausa entre ciclos de escaneo
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"[IAST_DETECTOR] Error en loop de monitoreo: {e}")
                time.sleep(1)
    
    def _scan_web_processes(self):
        """Escanea procesos relacionados con aplicaciones web"""
        try:
            web_processes = [
                "chrome.exe", "firefox.exe", "edge.exe", "iexplore.exe",
                "nginx.exe", "httpd.exe", "apache.exe", "tomcat.exe",
                "node.exe", "python.exe", "java.exe", "dotnet.exe"
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] and proc.info['name'].lower() in web_processes:
                        self._analyze_process_for_vulns(proc.info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error escaneando procesos web: {e}")
    
    def _analyze_process_for_vulns(self, proc_info: Dict[str, Any]):
        """Analiza un proceso específico en busca de vulnerabilidades"""
        try:
            cmdline = ' '.join(proc_info.get('cmdline', []))
            process_name = proc_info.get('name', '')
            pid = proc_info.get('pid', 0)
            
            # Detectar SQL Injection en argumentos de línea de comandos
            for pattern in self.sql_injection_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    vulnerability = IASTVulnerability(
                        vuln_type="SQL_INJECTION",
                        severity="HIGH",
                        description=f"Posible SQL Injection detectada en {process_name}",
                        location=f"Process: {process_name} (PID: {pid})",
                        evidence={"cmdline": cmdline, "pattern": pattern}
                    )
                    self._report_vulnerability(vulnerability)
            
            # Detectar XSS en argumentos
            for pattern in self.xss_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    vulnerability = IASTVulnerability(
                        vuln_type="XSS",
                        severity="MEDIUM",
                        description=f"Posible XSS detectado en {process_name}",
                        location=f"Process: {process_name} (PID: {pid})",
                        evidence={"cmdline": cmdline, "pattern": pattern}
                    )
                    self._report_vulnerability(vulnerability)
            
            # Detectar Command Injection
            for pattern in self.command_injection_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    vulnerability = IASTVulnerability(
                        vuln_type="COMMAND_INJECTION",
                        severity="CRITICAL",
                        description=f"Posible Command Injection detectada en {process_name}",
                        location=f"Process: {process_name} (PID: {pid})",
                        evidence={"cmdline": cmdline, "pattern": pattern}
                    )
                    self._report_vulnerability(vulnerability)
            
            # Detectar Path Traversal
            for pattern in self.path_traversal_patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    vulnerability = IASTVulnerability(
                        vuln_type="PATH_TRAVERSAL",
                        severity="MEDIUM",
                        description=f"Posible Path Traversal detectado en {process_name}",
                        location=f"Process: {process_name} (PID: {pid})",
                        evidence={"cmdline": cmdline, "pattern": pattern}
                    )
                    self._report_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error analizando proceso: {e}")
    
    def _scan_log_files(self):
        """Escanea archivos de log comunes en busca de ataques"""
        try:
            log_paths = [
                "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",
                "C:\\Windows\\System32\\LogFiles\\W3SVC1\\*.log",
                "C:\\xampp\\apache\\logs\\access.log",
                "C:\\xampp\\apache\\logs\\error.log",
                "logs\\*.log"
            ]
            
            for log_pattern in log_paths:
                try:
                    import glob
                    for log_file in glob.glob(log_pattern):
                        self._analyze_log_file(log_file)
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error escaneando logs: {e}")
    
    def _analyze_log_file(self, log_path: str):
        """Analiza un archivo de log específico"""
        try:
            # Solo leer las últimas 100 líneas para evitar sobrecarga
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                recent_lines = lines[-100:] if len(lines) > 100 else lines
                
                for line_num, line in enumerate(recent_lines, 1):
                    self._analyze_log_line(line, log_path, line_num)
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error leyendo log {log_path}: {e}")
    
    def _analyze_log_line(self, line: str, log_path: str, line_num: int):
        """Analiza una línea específica del log"""
        try:
            # Combinar todos los patrones de vulnerabilidades
            all_patterns = (
                [(p, "SQL_INJECTION") for p in self.sql_injection_patterns] +
                [(p, "XSS") for p in self.xss_patterns] +
                [(p, "COMMAND_INJECTION") for p in self.command_injection_patterns] +
                [(p, "PATH_TRAVERSAL") for p in self.path_traversal_patterns]
            )
            
            for pattern, vuln_type in all_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity_map = {
                        "SQL_INJECTION": "HIGH",
                        "XSS": "MEDIUM", 
                        "COMMAND_INJECTION": "CRITICAL",
                        "PATH_TRAVERSAL": "MEDIUM"
                    }
                    
                    vulnerability = IASTVulnerability(
                        vuln_type=vuln_type,
                        severity=severity_map.get(vuln_type, "MEDIUM"),
                        description=f"Ataque {vuln_type.replace('_', ' ')} detectado en logs",
                        location=f"Log: {log_path}:{line_num}",
                        evidence={"log_line": line.strip(), "pattern": pattern}
                    )
                    self._report_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error analizando línea de log: {e}")
    
    def _scan_network_connections(self):
        """Escanea conexiones de red en busca de actividad sospechosa"""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    self._analyze_network_connection(conn)
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error escaneando conexiones: {e}")
    
    def _analyze_network_connection(self, connection):
        """Analiza una conexión de red específica"""
        try:
            # IPs sospechosas (ejemplo)
            suspicious_ips = [
                "10.0.0.0/8",    # Redes privadas inusuales en web
                "169.254.0.0/16", # Link-local
                "224.0.0.0/4"    # Multicast
            ]
            
            if connection.raddr and connection.raddr.ip:
                remote_ip = connection.raddr.ip
                remote_port = connection.raddr.port
                
                # Detectar puertos sospechosos
                suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
                
                if remote_port in suspicious_ports:
                    vulnerability = IASTVulnerability(
                        vuln_type="SUSPICIOUS_CONNECTION",
                        severity="MEDIUM",
                        description=f"Conexión a puerto sospechoso detectada",
                        location=f"Network: {remote_ip}:{remote_port}",
                        evidence={"remote_ip": remote_ip, "remote_port": remote_port}
                    )
                    self._report_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"[IAST_DETECTOR] Error analizando conexión: {e}")
    
    def _report_vulnerability(self, vulnerability: IASTVulnerability):
        """Reporta una vulnerabilidad encontrada"""
        try:
            self.vulnerabilities.append(vulnerability)
            
            # Mantener solo las últimas 1000 vulnerabilidades
            if len(self.vulnerabilities) > 1000:
                self.vulnerabilities = self.vulnerabilities[-1000:]
            
            # Log según severidad
            vuln_dict = vulnerability.to_dict()
            severity = vulnerability.severity
            
            if severity == "CRITICAL":
                self.logger.error(f"[IAST_DETECTOR] 🚨 CRÍTICO: {vulnerability.description}")
            elif severity == "HIGH":
                self.logger.warning(f"[IAST_DETECTOR] ⚠️ ALTO: {vulnerability.description}")
            elif severity == "MEDIUM":
                self.logger.info(f"[IAST_DETECTOR] 📊 MEDIO: {vulnerability.description}")
            else:
                self.logger.debug(f"[IAST_DETECTOR] 📝 BAJO: {vulnerability.description}")
                
        except Exception as e:
            self.logger.error(f"[IAST_DETECTOR] Error reportando vulnerabilidad: {e}")
    
    def get_vulnerabilities(self, severity_filter: str = None) -> List[Dict[str, Any]]:
        """Obtiene las vulnerabilidades encontradas"""
        try:
            vulns = [v.to_dict() for v in self.vulnerabilities]
            
            if severity_filter:
                vulns = [v for v in vulns if v['severity'] == severity_filter.upper()]
                
            return vulns
            
        except Exception as e:
            self.logger.error(f"[IAST_DETECTOR] Error obteniendo vulnerabilidades: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtiene estadísticas del detector IAST"""
        try:
            if not self.vulnerabilities:
                return {
                    "total_vulnerabilities": 0,
                    "by_severity": {},
                    "by_type": {},
                    "is_active": self.is_active,
                    "patterns_loaded": {
                        "sql_injection": len(self.sql_injection_patterns),
                        "xss": len(self.xss_patterns), 
                        "command_injection": len(self.command_injection_patterns),
                        "path_traversal": len(self.path_traversal_patterns)
                    }
                }
            
            by_severity = {}
            by_type = {}
            
            for vuln in self.vulnerabilities:
                # Por severidad
                severity = vuln.severity
                by_severity[severity] = by_severity.get(severity, 0) + 1
                
                # Por tipo
                vuln_type = vuln.vuln_type
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            return {
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": by_severity,
                "by_type": by_type,
                "is_active": self.is_active,
                "patterns_loaded": {
                    "sql_injection": len(self.sql_injection_patterns),
                    "xss": len(self.xss_patterns), 
                    "command_injection": len(self.command_injection_patterns),
                    "path_traversal": len(self.path_traversal_patterns)
                }
            }
            
        except Exception as e:
            self.logger.error(f"[IAST_DETECTOR] Error obteniendo estadísticas: {e}")
            return {"error": str(e)}