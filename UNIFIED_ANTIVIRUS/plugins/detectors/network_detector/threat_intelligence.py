"""
🛡️ Threat Intelligence Manager - Gestión de Inteligencia de Amenazas
====================================================================

Componente especializado en la gestión e integración de fuentes de threat intelligence.

Implementa:
- Strategy Pattern: Diferentes fuentes de inteligencia (archivos, APIs, feeds)
- Cache Pattern: Almacenamiento eficiente de datos de reputación
- Observer Pattern: Actualización automática de feeds de amenazas
"""

import os
import sys
import json
import time
import logging
import asyncio
import threading
import requests
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


class ThreatIntelligenceManager:
    """
    🛡️ Gestor de inteligencia de amenazas para detección de red.

    Integra múltiples fuentes de threat intelligence:
    - IPs maliciosas conocidas
    - Dominios sospechosos y DGA
    - Análisis de reputación en tiempo real
    - Feeds de IOCs (Indicators of Compromise)
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("threat_intelligence")

        # Configuración de threat intelligence
        self.ti_config = config.get("threat_intelligence", {})
        self.enable_ip_reputation = self.ti_config.get("enable_ip_reputation", True)
        self.enable_domain_analysis = self.ti_config.get("enable_domain_analysis", True)
        self.cache_hours = self.ti_config.get("reputation_cache_hours", 24)

        # Archivos de datos
        self.malicious_ips_file = self.ti_config.get(
            "malicious_ips_file", "threat_intel/malicious_ips.txt"
        )
        self.suspicious_domains_file = self.ti_config.get(
            "suspicious_domains_file", "threat_intel/domains.txt"
        )

        # Datos en memoria
        self.malicious_ips: Set[str] = set()
        self.suspicious_domains: Set[str] = set()
        self.reputation_cache: Dict[str, Dict[str, Any]] = {}
        self.domain_cache: Dict[str, Dict[str, Any]] = {}

        # Control de actualizaciones
        self.last_update = datetime.now()
        self.update_lock = threading.Lock()

        # Métricas
        self.metrics = {
            "malicious_ips_loaded": 0,
            "suspicious_domains_loaded": 0,
            "reputation_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "api_calls": 0,
        }

    async def initialize(self) -> bool:
        """Inicializa el gestor de threat intelligence."""
        try:
            self.logger.info("🛡️ Inicializando Threat Intelligence Manager...")

            # Crear directorios necesarios
            await self._create_directories()

            # Cargar datos iniciales
            await self.load_malicious_ips()
            await self.load_suspicious_domains()

            # Inicializar caché de reputación
            await self.initialize_reputation_cache()

            # Cargar datos por defecto si no existen archivos
            if not self.malicious_ips and not self.suspicious_domains:
                await self._load_default_threat_data()

            self.logger.info("✅ Threat Intelligence Manager inicializado")
            return True

        except Exception as e:
            self.logger.error(f"❌ Error inicializando Threat Intelligence: {e}")
            return False

    async def _create_directories(self):
        """Crea directorios necesarios para threat intelligence."""
        threat_intel_dir = Path("threat_intel")
        threat_intel_dir.mkdir(exist_ok=True)

        cache_dir = Path("cache")
        cache_dir.mkdir(exist_ok=True)

    # ==================== STRATEGY PATTERN - FUENTES DE DATOS ====================

    async def load_malicious_ips(self) -> bool:
        """
        🎯 Strategy: Carga IPs maliciosas desde archivo.
        """
        try:
            malicious_ips_path = Path(self.malicious_ips_file)

            if malicious_ips_path.exists():
                with open(malicious_ips_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Validar formato de IP
                            if self._is_valid_ip(line):
                                self.malicious_ips.add(line)

                self.metrics["malicious_ips_loaded"] = len(self.malicious_ips)
                self.logger.info(
                    f"📋 Cargadas {len(self.malicious_ips)} IPs maliciosas"
                )
                return True
            else:
                self.logger.warning(
                    f"⚠️ Archivo de IPs maliciosas no encontrado: {malicious_ips_path}"
                )
                # Crear archivo con datos por defecto
                await self._create_default_malicious_ips_file()
                return False

        except Exception as e:
            self.logger.error(f"❌ Error cargando IPs maliciosas: {e}")
            return False

    async def load_suspicious_domains(self) -> bool:
        """
        🎯 Strategy: Carga dominios sospechosos desde archivo.
        """
        try:
            suspicious_domains_path = Path(self.suspicious_domains_file)

            if suspicious_domains_path.exists():
                with open(suspicious_domains_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Validar formato de dominio
                            if self._is_valid_domain(line):
                                self.suspicious_domains.add(line.lower())

                self.metrics["suspicious_domains_loaded"] = len(self.suspicious_domains)
                self.logger.info(
                    f"📋 Cargados {len(self.suspicious_domains)} dominios sospechosos"
                )
                return True
            else:
                self.logger.warning(
                    f"⚠️ Archivo de dominios sospechosos no encontrado: {suspicious_domains_path}"
                )
                # Crear archivo con datos por defecto
                await self._create_default_suspicious_domains_file()
                return False

        except Exception as e:
            self.logger.error(f"❌ Error cargando dominios sospechosos: {e}")
            return False

    async def _load_default_threat_data(self):
        """Carga datos de amenaza por defecto."""
        # IPs maliciosas conocidas (ejemplos)
        default_malicious_ips = [
            "185.220.100.240",  # Tor exit node conocido
            "185.220.100.241",
            "185.220.100.242",
            "94.102.49.190",  # Botnet conocido
            "94.102.49.191",
        ]

        # Dominios sospechosos (ejemplos)
        default_suspicious_domains = [
            "tempuri.org",
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "malware-traffic-analysis.net",
        ]

        self.malicious_ips.update(default_malicious_ips)
        self.suspicious_domains.update(default_suspicious_domains)

        self.metrics["malicious_ips_loaded"] = len(self.malicious_ips)
        self.metrics["suspicious_domains_loaded"] = len(self.suspicious_domains)

        self.logger.info("📋 Datos de amenaza por defecto cargados")

    async def _create_default_malicious_ips_file(self):
        """Crea archivo por defecto de IPs maliciosas."""
        content = """# Archivo de IPs maliciosas conocidas
# Formato: una IP por línea
# Líneas que comienzan con # son comentarios

# Tor exit nodes conocidos
185.220.100.240
185.220.100.241
185.220.100.242

# Botnets conocidos  
94.102.49.190
94.102.49.191

# C&C servers conocidos
198.23.140.37
185.159.157.154

# Agregue más IPs maliciosas aquí...
"""

        malicious_ips_path = Path(self.malicious_ips_file)
        malicious_ips_path.parent.mkdir(parents=True, exist_ok=True)

        with open(malicious_ips_path, "w", encoding="utf-8") as f:
            f.write(content)

        self.logger.info(f"📝 Creado archivo por defecto: {malicious_ips_path}")

    async def _create_default_suspicious_domains_file(self):
        """Crea archivo por defecto de dominios sospechosos."""
        content = """# Archivo de dominios sospechosos
# Formato: un dominio por línea
# Líneas que comienzan con # son comentarios

# URL shorteners sospechosos
bit.ly
tinyurl.com
t.co
short.link

# Dominios DGA conocidos
tempuri.org
example-malware.com
malware-traffic-analysis.net

# Dominios de phishing conocidos
phishing-example.com
fake-bank.net

# Agregue más dominios sospechosos aquí...
"""

        suspicious_domains_path = Path(self.suspicious_domains_file)
        suspicious_domains_path.parent.mkdir(parents=True, exist_ok=True)

        with open(suspicious_domains_path, "w", encoding="utf-8") as f:
            f.write(content)

        self.logger.info(f"📝 Creado archivo por defecto: {suspicious_domains_path}")

    # ==================== CACHE PATTERN ====================

    async def initialize_reputation_cache(self) -> bool:
        """Inicializa el caché de reputación."""
        try:
            cache_file = Path("cache/reputation_cache.json")

            if cache_file.exists():
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)

                # Filtrar entradas caducadas
                current_time = datetime.now()
                valid_cache = {}

                for ip, data in cached_data.items():
                    cache_time = datetime.fromisoformat(
                        data.get("cached_at", "1970-01-01")
                    )
                    if (current_time - cache_time).hours < self.cache_hours:
                        valid_cache[ip] = data

                self.reputation_cache = valid_cache
                self.logger.info(
                    f"💾 Caché de reputación cargado: {len(valid_cache)} entradas"
                )

            return True

        except Exception as e:
            self.logger.error(f"❌ Error inicializando caché: {e}")
            return False

    async def save_reputation_cache(self):
        """Guarda el caché de reputación en disco."""
        try:
            cache_file = Path("cache/reputation_cache.json")
            cache_file.parent.mkdir(exist_ok=True)

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    self.reputation_cache, f, indent=2, ensure_ascii=False, default=str
                )

            self.logger.info(
                f"💾 Caché guardado: {len(self.reputation_cache)} entradas"
            )

        except Exception as e:
            self.logger.error(f"❌ Error guardando caché: {e}")

    # ==================== CONSULTAS PRINCIPALES ====================

    async def is_malicious_ip(self, ip: str) -> bool:
        """
        🔍 Verifica si una IP es maliciosa según threat intelligence.
        """
        if not ip or not self._is_valid_ip(ip):
            return False

        # Verificar en lista local de IPs maliciosas
        if ip in self.malicious_ips:
            self.logger.warning(f"🚨 IP maliciosa detectada (lista local): {ip}")
            return True

        # Verificar en caché de reputación
        if self.enable_ip_reputation:
            reputation_data = await self.get_ip_reputation_cached(ip)
            if reputation_data:
                reputation_score = reputation_data.get("reputation_score", 0.5)
                if reputation_score > 0.8:  # Alto riesgo
                    self.logger.warning(
                        f"🚨 IP maliciosa detectada (reputación): {ip} (score: {reputation_score})"
                    )
                    return True

        return False

    async def is_suspicious_domain(self, domain: str) -> bool:
        """
        🔍 Verifica si un dominio es sospechoso según threat intelligence.
        """
        if not domain or not self._is_valid_domain(domain):
            return False

        domain = domain.lower()

        # Verificar en lista local de dominios sospechosos
        if domain in self.suspicious_domains:
            self.logger.warning(
                f"🚨 Dominio sospechoso detectado (lista local): {domain}"
            )
            return True

        # Verificar subdominios de dominios conocidos
        for suspicious_domain in self.suspicious_domains:
            if domain.endswith("." + suspicious_domain):
                self.logger.warning(f"🚨 Subdominio sospechoso detectado: {domain}")
                return True

        # Análisis heurístico de dominio
        if self._is_domain_suspicious_heuristic(domain):
            self.logger.warning(f"🚨 Dominio sospechoso (heurística): {domain}")
            return True

        return False

    async def get_ip_reputation_cached(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        🎯 Obtiene reputación de IP usando caché inteligente.
        """
        if not self.enable_ip_reputation:
            return None

        # Verificar caché primero
        if ip in self.reputation_cache:
            cache_data = self.reputation_cache[ip]
            cached_at = datetime.fromisoformat(
                cache_data.get("cached_at", "1970-01-01")
            )

            # Verificar si el caché sigue siendo válido
            if (datetime.now() - cached_at).seconds < (self.cache_hours * 3600):
                self.metrics["cache_hits"] += 1
                return cache_data

        # Cache miss - obtener nueva reputación
        self.metrics["cache_misses"] += 1
        reputation_data = await self._fetch_ip_reputation(ip)

        if reputation_data:
            # Guardar en caché
            reputation_data["cached_at"] = datetime.now().isoformat()
            self.reputation_cache[ip] = reputation_data

        return reputation_data

    async def _fetch_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        🌐 Obtiene reputación de IP desde fuentes externas.

        Implementa Strategy Pattern para diferentes APIs de reputación.
        """
        try:
            self.metrics["api_calls"] += 1

            # Strategy 1: Análisis local basado en rangos conocidos
            local_reputation = self._analyze_ip_local_reputation(ip)

            # Strategy 2: Simulación de API de reputación (sin API real para demo)
            simulated_reputation = self._simulate_ip_reputation_api(ip)

            # Strategy 3: Análisis heurístico
            heuristic_reputation = self._analyze_ip_heuristic(ip)

            # Combinar resultados (promedio ponderado)
            combined_score = (
                local_reputation * 0.4
                + simulated_reputation * 0.4
                + heuristic_reputation * 0.2
            )

            reputation_data = {
                "ip": ip,
                "reputation_score": combined_score,
                "local_score": local_reputation,
                "simulated_score": simulated_reputation,
                "heuristic_score": heuristic_reputation,
                "analysis_timestamp": datetime.now().isoformat(),
                "source": "combined_analysis",
            }

            self.logger.info(f"📊 Reputación IP {ip}: {combined_score:.3f}")
            return reputation_data

        except Exception as e:
            self.logger.error(f"❌ Error obteniendo reputación de {ip}: {e}")
            return None

    # ==================== ANÁLISIS DE REPUTACIÓN ====================

    def _analyze_ip_local_reputation(self, ip: str) -> float:
        """Strategy 1: Análisis local de reputación por rangos de IP."""
        try:
            # Rangos de IP conocidos como problemáticos
            suspicious_ranges = [
                ("185.220.", 0.9),  # Tor network
                ("94.102.49.", 0.8),  # Known botnet range
                ("198.23.140.", 0.9),  # C&C servers
                ("185.159.157.", 0.8),  # Malware hosting
            ]

            for range_prefix, risk_score in suspicious_ranges:
                if ip.startswith(range_prefix):
                    return risk_score

            # Rangos legítimos conocidos
            legitimate_ranges = [
                ("8.8.", 0.1),  # Google DNS
                ("1.1.1.", 0.1),  # Cloudflare DNS
                ("208.67.222.", 0.1),  # OpenDNS
                ("172.217.", 0.1),  # Google services
                ("13.", 0.2),  # Amazon AWS (legítimo pero puede hospedar malware)
                ("52.", 0.2),  # Amazon AWS
            ]

            for range_prefix, trust_score in legitimate_ranges:
                if ip.startswith(range_prefix):
                    return trust_score

            # IP desconocida - riesgo medio
            return 0.5

        except Exception:
            return 0.5

    def _simulate_ip_reputation_api(self, ip: str) -> float:
        """Strategy 2: Simulación de API de reputación (para demo)."""
        try:
            # Simulación basada en características de la IP
            ip_parts = ip.split(".")

            # Análisis heurístico simple
            last_octet = int(ip_parts[-1])

            # IPs que terminan en ciertos números son más sospechosas (simulación)
            if last_octet in [240, 241, 242, 243, 244]:
                return 0.8  # Alto riesgo
            elif last_octet in [1, 254, 255]:
                return 0.6  # Medio riesgo (gateways, broadcasts)
            elif 200 <= last_octet <= 250:
                return 0.4  # Medio-bajo riesgo
            else:
                return 0.3  # Bajo riesgo

        except Exception:
            return 0.5

    def _analyze_ip_heuristic(self, ip: str) -> float:
        """Strategy 3: Análisis heurístico de la IP."""
        try:
            risk_score = 0.0

            # Verificar si está en rangos problemáticos
            ip_parts = [int(part) for part in ip.split(".")]

            # Rangos privados/locales tienen bajo riesgo
            if (
                (ip_parts[0] == 192 and ip_parts[1] == 168)
                or (ip_parts[0] == 10)
                or (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31)
            ):
                return 0.1

            # Rangos de clase A sospechosos
            if ip_parts[0] in [185, 94, 198, 31, 46]:
                risk_score += 0.3

            # Patrones sospechosos en octetos
            if ip_parts[1] in [220, 102, 23]:
                risk_score += 0.2

            # IPs secuenciales (posible botnet)
            if ip_parts[2] in [100, 140, 49, 157]:
                risk_score += 0.2

            # Último octeto alto (servicios no estándar)
            if ip_parts[3] > 240:
                risk_score += 0.1

            return min(risk_score, 1.0)

        except Exception:
            return 0.5

    def _is_domain_suspicious_heuristic(self, domain: str) -> bool:
        """Análisis heurístico de dominios sospechosos."""
        try:
            # Longitud anómala
            if len(domain) > 50 or len(domain) < 4:
                return True

            # Muchos números (posible DGA)
            num_count = sum(1 for c in domain if c.isdigit())
            if num_count > len(domain) * 0.3:  # Más de 30% números
                return True

            # Muchos guiones (posible DGA)
            dash_count = domain.count("-")
            if dash_count > 3:
                return True

            # Subdominios excesivos
            subdomain_count = domain.count(".")
            if subdomain_count > 4:
                return True

            # Patrones DGA comunes
            dga_patterns = [
                "tempuri",
                "malware",
                "botnet",
                "c2server",
                "payload",
                "exploit",
                "backdoor",
            ]

            for pattern in dga_patterns:
                if pattern in domain.lower():
                    return True

            # Entropía alta (dominio aleatorio)
            entropy = self._calculate_domain_entropy(domain)
            if entropy > 4.5:  # Entropía alta indica aleatoriedad
                return True

            return False

        except Exception:
            return False

    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calcula la entropía de un dominio para detectar DGA."""
        try:
            import math
            from collections import Counter

            # Contar frecuencia de caracteres
            char_counts = Counter(domain.lower())
            domain_length = len(domain)

            # Calcular entropía de Shannon
            entropy = 0.0
            for count in char_counts.values():
                probability = count / domain_length
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            return entropy

        except Exception:
            return 0.0

    # ==================== ACTUALIZACIÓN DE FEEDS ====================

    async def update_threat_feeds(self):
        """
        🔄 Actualiza feeds de threat intelligence.
        """
        try:
            self.logger.info("🔄 Actualizando feeds de threat intelligence...")

            with self.update_lock:
                # Recargar archivos locales
                await self.load_malicious_ips()
                await self.load_suspicious_domains()

                # Guardar caché actualizado
                await self.save_reputation_cache()

                # Actualizar timestamp
                self.last_update = datetime.now()

            self.logger.info("✅ Feeds de threat intelligence actualizados")

        except Exception as e:
            self.logger.error(f"❌ Error actualizando feeds: {e}")

    def add_malicious_ip(self, ip: str, source: str = "manual"):
        """Agrega una IP maliciosa dinámicamente."""
        if self._is_valid_ip(ip):
            self.malicious_ips.add(ip)
            self.logger.warning(f"➕ IP maliciosa agregada: {ip} (fuente: {source})")

    def add_suspicious_domain(self, domain: str, source: str = "manual"):
        """Agrega un dominio sospechoso dinámicamente."""
        if self._is_valid_domain(domain):
            self.suspicious_domains.add(domain.lower())
            self.logger.warning(
                f"➕ Dominio sospechoso agregado: {domain} (fuente: {source})"
            )

    # ==================== UTILIDADES ====================

    def _is_valid_ip(self, ip: str) -> bool:
        """Valida formato de dirección IP."""
        try:
            parts = ip.split(".")
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Valida formato de dominio."""
        try:
            # Verificaciones básicas
            if not domain or len(domain) > 253:
                return False

            # Debe contener al menos un punto
            if "." not in domain:
                return False

            # No puede empezar o terminar con punto o guión
            if (
                domain.startswith(".")
                or domain.endswith(".")
                or domain.startswith("-")
                or domain.endswith("-")
            ):
                return False

            # Verificar cada parte del dominio
            parts = domain.split(".")
            for part in parts:
                if not part or len(part) > 63:
                    return False
                # Solo letras, números y guiones
                if not all(c.isalnum() or c == "-" for c in part):
                    return False

            return True

        except:
            return False

    def get_threat_intelligence_summary(self) -> Dict[str, Any]:
        """Obtiene resumen del estado de threat intelligence."""
        return {
            "malicious_ips_count": len(self.malicious_ips),
            "suspicious_domains_count": len(self.suspicious_domains),
            "reputation_cache_size": len(self.reputation_cache),
            "last_update": self.last_update.isoformat(),
            "metrics": self.metrics,
            "configuration": {
                "enable_ip_reputation": self.enable_ip_reputation,
                "enable_domain_analysis": self.enable_domain_analysis,
                "cache_hours": self.cache_hours,
            },
        }

    def cleanup_old_cache(self):
        """Limpia entradas antiguas del caché."""
        current_time = datetime.now()
        old_entries = []

        for ip, data in self.reputation_cache.items():
            cache_time = datetime.fromisoformat(data.get("cached_at", "1970-01-01"))
            if (current_time - cache_time).seconds > (self.cache_hours * 3600):
                old_entries.append(ip)

        for ip in old_entries:
            del self.reputation_cache[ip]

        if old_entries:
            self.logger.info(f"🧹 Limpiadas {len(old_entries)} entradas del caché")


# ==================== TESTING ====================


def main():
    """Función de testing del ThreatIntelligenceManager."""
    import asyncio

    async def test_threat_intelligence():
        """Test del gestor de threat intelligence."""
        print("🧪 Testing Threat Intelligence Manager...")

        # Configuración de prueba
        config = {
            "threat_intelligence": {
                "enable_ip_reputation": True,
                "enable_domain_analysis": True,
                "reputation_cache_hours": 24,
            }
        }

        # Crear gestor
        ti_manager = ThreatIntelligenceManager(config)

        # Test inicialización
        success = await ti_manager.initialize()
        print(f"✅ Inicialización: {'OK' if success else 'FALLO'}")

        if success:
            # Test verificación de IP maliciosa
            test_ips = ["185.220.100.240", "8.8.8.8", "192.168.1.1"]
            for ip in test_ips:
                is_malicious = await ti_manager.is_malicious_ip(ip)
                print(f"🔍 IP {ip}: {'MALICIOSA' if is_malicious else 'LIMPIA'}")

            # Test verificación de dominio sospechoso
            test_domains = ["tempuri.org", "google.com", "malware-traffic-analysis.net"]
            for domain in test_domains:
                is_suspicious = await ti_manager.is_suspicious_domain(domain)
                print(
                    f"🔍 Dominio {domain}: {'SOSPECHOSO' if is_suspicious else 'LIMPIO'}"
                )

            # Test reputación de IP
            reputation = await ti_manager.get_ip_reputation_cached("185.220.100.240")
            if reputation:
                print(f"📊 Reputación: {reputation.get('reputation_score', 0):.3f}")

            # Test resumen
            summary = ti_manager.get_threat_intelligence_summary()
            print(f"📋 IPs maliciosas: {summary['malicious_ips_count']}")
            print(f"📋 Dominios sospechosos: {summary['suspicious_domains_count']}")

        print("🏁 Test completado")

    # Ejecutar test
    asyncio.run(test_threat_intelligence())


if __name__ == "__main__":
    main()
