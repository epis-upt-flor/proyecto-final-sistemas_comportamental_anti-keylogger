"""
🌍 IP Analyzer - Análisis Detallado de Direcciones IP
====================================================

Componente especializado en análisis de direcciones IP para detección de amenazas.

Implementa:
- Strategy Pattern: Diferentes métodos de análisis según tipo de IP
- Adapter Pattern: Adaptadores para diferentes APIs de geolocalización
- Cache Pattern: Almacenamiento eficiente de análisis previos
"""

import os
import sys
import json
import time
import logging
import requests
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, asdict
import ipaddress


@dataclass
class IPAnalysisResult:
    """Resultado del análisis de una dirección IP."""
    ip: str
    country: Optional[str]
    region: Optional[str] 
    city: Optional[str]
    isp: Optional[str]
    organization: Optional[str]
    asn: Optional[str]
    reputation_score: float
    threat_types: List[str]
    is_tor: bool
    is_vpn: bool
    is_proxy: bool
    is_malicious: bool
    analysis_timestamp: datetime
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['analysis_timestamp'] = self.analysis_timestamp.isoformat()
        return data


class IPAnalyzer:
    """
    🌍 Analizador detallado de direcciones IP para detección de amenazas.
    
    Funcionalidades:
    - Geolocalización de IPs
    - Análisis de reputación
    - Detección de Tor/VPN/Proxy
    - Identificación de ISPs y organizaciones
    - Correlación con threat intelligence
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("ip_analyzer")
        
        # Configuración
        self.ti_config = config.get('threat_intelligence', {})
        self.enable_geolocation = self.ti_config.get('enable_geolocation', True)
        self.cache_hours = self.ti_config.get('reputation_cache_hours', 24)
        
        # Caché de análisis
        self.analysis_cache: Dict[str, IPAnalysisResult] = {}
        
        # Datos estáticos cargados
        self.tor_exit_nodes: Set[str] = set()
        self.known_vpn_ranges: List[Tuple[str, str]] = []
        self.malicious_asns: Set[str] = set()
        
        # Métricas
        self.metrics = {
            'ips_analyzed': 0,
            'geolocation_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'tor_nodes_detected': 0,
            'vpn_connections_detected': 0,
            'malicious_ips_detected': 0
        }
    
    async def initialize(self) -> bool:
        """Inicializa el analizador de IPs."""
        try:
            self.logger.info("🌍 Inicializando IP Analyzer...")
            
            # Cargar datos estáticos
            await self._load_static_data()
            
            # Cargar caché previo
            await self._load_analysis_cache()
            
            self.logger.info("✅ IP Analyzer inicializado")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error inicializando IP Analyzer: {e}")
            return False
    
    # ==================== STRATEGY PATTERN ====================
    
    async def analyze_ip(self, ip: str) -> Optional[IPAnalysisResult]:
        """
        🎯 Strategy Pattern: Análisis completo de IP según características.
        
        Selecciona estrategia de análisis:
        1. IP privada -> Análisis local básico
        2. IP pública -> Análisis completo con geolocalización
        3. IP en whitelist -> Análisis simplificado
        """
        try:
            if not self._is_valid_ip(ip):
                return None
            
            # Verificar caché primero
            cached_result = await self._get_cached_analysis(ip)
            if cached_result:
                self.metrics['cache_hits'] += 1
                return cached_result
            
            self.metrics['cache_misses'] += 1
            self.metrics['ips_analyzed'] += 1
            
            # Strategy 1: IP privada
            if self._is_private_ip(ip):
                return await self._analyze_private_ip(ip)
            
            # Strategy 2: IP pública
            return await self._analyze_public_ip(ip)
            
        except Exception as e:
            self.logger.error(f"❌ Error analizando IP {ip}: {e}")
            return None
    
    async def _analyze_private_ip(self, ip: str) -> IPAnalysisResult:
        """Strategy 1: Análisis de IP privada."""
        result = IPAnalysisResult(
            ip=ip,
            country="Local",
            region="Private Network",
            city="Local",
            isp="Private",
            organization="Local Network",
            asn="Private",
            reputation_score=0.1,  # IPs privadas son generalmente seguras
            threat_types=[],
            is_tor=False,
            is_vpn=False,
            is_proxy=False,
            is_malicious=False,
            analysis_timestamp=datetime.now(),
            confidence=0.95
        )
        
        # Cachear resultado
        self.analysis_cache[ip] = result
        return result
    
    async def _analyze_public_ip(self, ip: str) -> IPAnalysisResult:
        """Strategy 2: Análisis completo de IP pública."""
        # Inicializar resultado base
        result = IPAnalysisResult(
            ip=ip,
            country=None,
            region=None,
            city=None,
            isp=None,
            organization=None,
            asn=None,
            reputation_score=0.5,  # Neutral por defecto
            threat_types=[],
            is_tor=False,
            is_vpn=False,
            is_proxy=False,
            is_malicious=False,
            analysis_timestamp=datetime.now(),
            confidence=0.7
        )
        
        # Análisis de geolocalización
        if self.enable_geolocation:
            geo_data = await self._get_ip_geolocation(ip)
            if geo_data:
                result.country = geo_data.get('country')
                result.region = geo_data.get('region')
                result.city = geo_data.get('city')
                result.isp = geo_data.get('isp')
                result.organization = geo_data.get('organization')
                result.asn = geo_data.get('asn')
        
        # Análisis de Tor
        result.is_tor = await self._is_tor_exit_node(ip)
        if result.is_tor:
            result.threat_types.append('tor_exit_node')
            result.reputation_score += 0.3
            self.metrics['tor_nodes_detected'] += 1
        
        # Análisis de VPN/Proxy
        result.is_vpn, result.is_proxy = await self._detect_vpn_proxy(ip)
        if result.is_vpn:
            result.threat_types.append('vpn_service')
            result.reputation_score += 0.2
            self.metrics['vpn_connections_detected'] += 1
        
        if result.is_proxy:
            result.threat_types.append('proxy_service')
            result.reputation_score += 0.2
        
        # Análisis de ASN malicioso
        if result.asn and await self._is_malicious_asn(result.asn):
            result.threat_types.append('malicious_asn')
            result.reputation_score += 0.3
        
        # Análisis de país de alto riesgo
        if result.country and self._is_high_risk_country(result.country):
            result.threat_types.append('high_risk_country')
            result.reputation_score += 0.1
        
        # Determinar si es maliciosa
        result.is_malicious = result.reputation_score > 0.7
        if result.is_malicious:
            self.metrics['malicious_ips_detected'] += 1
        
        # Ajustar confianza basada en datos disponibles
        confidence_factors = [
            result.country is not None,
            result.isp is not None,
            result.asn is not None
        ]
        result.confidence = 0.5 + (sum(confidence_factors) * 0.15)
        
        # Cachear resultado
        self.analysis_cache[ip] = result
        return result
    
    # ==================== ADAPTER PATTERN ====================
    
    async def _get_ip_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        🔌 Adapter Pattern: Adapta diferentes APIs de geolocalización.
        """
        try:
            self.metrics['geolocation_queries'] += 1
            
            # Adapter 1: API simulada (para demo)
            geo_data = await self._simulate_geolocation_api(ip)
            
            # En una implementación real, aquí se integrarían APIs como:
            # - MaxMind GeoIP2
            # - ipapi.co
            # - ip-api.com
            # - GeoJS
            
            return geo_data
            
        except Exception as e:
            self.logger.error(f"❌ Error obteniendo geolocalización de {ip}: {e}")
            return None
    
    async def _simulate_geolocation_api(self, ip: str) -> Dict[str, Any]:
        """Adapter: Simulación de API de geolocalización."""
        try:
            # Simulación basada en rangos de IP conocidos
            ip_parts = [int(part) for part in ip.split('.')]
            
            # Simulación básica por primer octeto
            first_octet = ip_parts[0]
            
            geo_mapping = {
                185: {
                    'country': 'Netherlands',
                    'region': 'North Holland',
                    'city': 'Amsterdam',
                    'isp': 'Hosting Provider',
                    'organization': 'VPS Hosting',
                    'asn': 'AS60781'
                },
                94: {
                    'country': 'Russia',
                    'region': 'Moscow',
                    'city': 'Moscow',
                    'isp': 'Russian Telecom',
                    'organization': 'Unknown',
                    'asn': 'AS12389'
                },
                198: {
                    'country': 'United States',
                    'region': 'California',
                    'city': 'Los Angeles',
                    'isp': 'Hosting Solutions',
                    'organization': 'Data Center',
                    'asn': 'AS23033'
                },
                8: {
                    'country': 'United States',
                    'region': 'California',
                    'city': 'Mountain View',
                    'isp': 'Google LLC',
                    'organization': 'Google',
                    'asn': 'AS15169'
                },
                1: {
                    'country': 'United States',
                    'region': 'California',
                    'city': 'San Francisco',
                    'isp': 'Cloudflare',
                    'organization': 'Cloudflare Inc',
                    'asn': 'AS13335'
                }
            }
            
            return geo_mapping.get(first_octet, {
                'country': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown',
                'isp': 'Unknown ISP',
                'organization': 'Unknown',
                'asn': f'AS{first_octet * 100}'
            })
            
        except Exception as e:
            self.logger.error(f"❌ Error simulando geolocalización: {e}")
            return {}
    
    # ==================== ANÁLISIS ESPECIALIZADO ====================
    
    async def _is_tor_exit_node(self, ip: str) -> bool:
        """Verifica si la IP es un nodo de salida de Tor."""
        try:
            # Verificar en lista cargada
            if ip in self.tor_exit_nodes:
                return True
            
            # Verificación heurística por rangos conocidos de Tor
            tor_ranges = [
                '185.220.100.',
                '185.220.101.',
                '185.220.102.',
                '199.87.154.',
                '176.10.104.',
                '51.15.43.'
            ]
            
            for tor_range in tor_ranges:
                if ip.startswith(tor_range):
                    self.tor_exit_nodes.add(ip)  # Cachear para futuras consultas
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Error verificando nodo Tor: {e}")
            return False
    
    async def _detect_vpn_proxy(self, ip: str) -> Tuple[bool, bool]:
        """Detecta si la IP pertenece a servicios VPN o proxy."""
        try:
            is_vpn = False
            is_proxy = False
            
            # Rangos conocidos de VPN (simulación)
            vpn_ranges = [
                ('185.159.', 'ExpressVPN'),
                ('104.238.', 'NordVPN'),
                ('146.70.', 'Surfshark'),
                ('192.42.', 'ProtonVPN'),
                ('89.187.', 'CyberGhost')
            ]
            
            for range_prefix, service in vpn_ranges:
                if ip.startswith(range_prefix):
                    is_vpn = True
                    break
            
            # Detección de proxies por puertos comunes en el ASN
            proxy_asns = ['AS60781', 'AS12389', 'AS23033']
            
            # En una implementación real, aquí se verificaría el ASN de la IP
            # Por ahora simulamos basado en rangos
            proxy_ranges = ['94.102.', '198.23.', '31.14.']
            for proxy_range in proxy_ranges:
                if ip.startswith(proxy_range):
                    is_proxy = True
                    break
            
            return is_vpn, is_proxy
            
        except Exception as e:
            self.logger.error(f"❌ Error detectando VPN/Proxy: {e}")
            return False, False
    
    async def _is_malicious_asn(self, asn: str) -> bool:
        """Verifica si el ASN es conocido por alojar malware."""
        try:
            # ASNs conocidos por actividad maliciosa (ejemplos)
            malicious_asns = {
                'AS60781',  # Hosting conocido por malware
                'AS12389',  # ASN comprometido
                'AS23033',  # Hosting sin control
                'AS39743',  # Bulletproof hosting
                'AS48693'   # Hosting sospechoso
            }
            
            return asn in malicious_asns
            
        except Exception:
            return False
    
    def _is_high_risk_country(self, country: str) -> bool:
        """Determina si un país tiene alto riesgo de actividad maliciosa."""
        # Lista de países con alta actividad de malware (ejemplo)
        high_risk_countries = {
            'CN', 'RU', 'KP', 'IR', 'PK', 'VN', 'TH', 'IN'
        }
        
        # También verificar nombres completos
        high_risk_names = {
            'China', 'Russia', 'North Korea', 'Iran', 'Pakistan',
            'Vietnam', 'Thailand', 'India'
        }
        
        return (country in high_risk_countries or 
                country in high_risk_names)
    
    # ==================== CACHE MANAGEMENT ====================
    
    async def _get_cached_analysis(self, ip: str) -> Optional[IPAnalysisResult]:
        """Obtiene análisis desde caché si está vigente."""
        if ip not in self.analysis_cache:
            return None
        
        cached_result = self.analysis_cache[ip]
        
        # Verificar si el caché sigue vigente
        cache_age = datetime.now() - cached_result.analysis_timestamp
        if cache_age.total_seconds() > (self.cache_hours * 3600):
            # Caché expirado
            del self.analysis_cache[ip]
            return None
        
        return cached_result
    
    async def _load_analysis_cache(self):
        """Carga caché de análisis desde disco."""
        try:
            cache_file = Path('cache/ip_analysis_cache.json')
            
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                
                # Reconstruir objetos IPAnalysisResult
                current_time = datetime.now()
                valid_cache = {}
                
                for ip, analysis_dict in cached_data.items():
                    try:
                        # Convertir timestamp de vuelta a datetime
                        analysis_dict['analysis_timestamp'] = datetime.fromisoformat(
                            analysis_dict['analysis_timestamp']
                        )
                        
                        # Verificar si sigue vigente
                        cache_age = current_time - analysis_dict['analysis_timestamp']
                        if cache_age.total_seconds() < (self.cache_hours * 3600):
                            valid_cache[ip] = IPAnalysisResult(**analysis_dict)
                    
                    except Exception as e:
                        self.logger.warning(f"⚠️ Error cargando entrada de caché para {ip}: {e}")
                        continue
                
                self.analysis_cache = valid_cache
                self.logger.info(f"💾 Caché de análisis IP cargado: {len(valid_cache)} entradas")
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando caché de análisis: {e}")
    
    async def save_analysis_cache(self):
        """Guarda caché de análisis en disco."""
        try:
            cache_data = {}
            
            for ip, result in self.analysis_cache.items():
                cache_data[ip] = result.to_dict()
            
            cache_file = Path('cache/ip_analysis_cache.json')
            cache_file.parent.mkdir(exist_ok=True)
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Caché de análisis guardado: {len(cache_data)} entradas")
            
        except Exception as e:
            self.logger.error(f"❌ Error guardando caché: {e}")
    
    # ==================== CARGA DE DATOS ESTÁTICOS ====================
    
    async def _load_static_data(self):
        """Carga datos estáticos para análisis."""
        try:
            # Cargar nodos Tor conocidos
            await self._load_tor_exit_nodes()
            
            # Cargar rangos VPN conocidos
            await self._load_vpn_ranges()
            
            # Cargar ASNs maliciosos
            await self._load_malicious_asns()
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando datos estáticos: {e}")
    
    async def _load_tor_exit_nodes(self):
        """Carga lista de nodos de salida de Tor."""
        try:
            # En una implementación real, esto se descargaría desde:
            # https://check.torproject.org/api/bulk
            
            # Lista estática de ejemplo
            tor_nodes = [
                '185.220.100.240',
                '185.220.100.241', 
                '185.220.100.242',
                '199.87.154.255',
                '176.10.104.240',
                '51.15.43.205'
            ]
            
            self.tor_exit_nodes = set(tor_nodes)
            self.logger.info(f"🧅 Nodos Tor cargados: {len(self.tor_exit_nodes)}")
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando nodos Tor: {e}")
    
    async def _load_vpn_ranges(self):
        """Carga rangos de IP de servicios VPN conocidos."""
        try:
            # Rangos VPN conocidos (ejemplo)
            vpn_ranges = [
                ('185.159.0.0', '185.159.255.255'),  # ExpressVPN
                ('104.238.0.0', '104.238.255.255'),  # NordVPN
                ('146.70.0.0', '146.70.255.255'),    # Surfshark
            ]
            
            self.known_vpn_ranges = vpn_ranges
            self.logger.info(f"🔒 Rangos VPN cargados: {len(vpn_ranges)}")
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando rangos VPN: {e}")
    
    async def _load_malicious_asns(self):
        """Carga ASNs conocidos por actividad maliciosa."""
        try:
            malicious_asns = {
                'AS60781',  # Hosting malicioso conocido
                'AS12389',  # ASN comprometido
                'AS23033',  # Hosting sin control
                'AS39743',  # Bulletproof hosting
            }
            
            self.malicious_asns = malicious_asns
            self.logger.info(f"⚠️ ASNs maliciosos cargados: {len(malicious_asns)}")
            
        except Exception as e:
            self.logger.error(f"❌ Error cargando ASNs maliciosos: {e}")
    
    # ==================== UTILIDADES ====================
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Valida formato de dirección IP."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Determina si una IP es privada."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    # ==================== API PÚBLICA ====================
    
    async def get_ip_reputation(self, ip: str) -> Optional[float]:
        """Obtiene score de reputación de una IP (0.0 = buena, 1.0 = maliciosa)."""
        analysis = await self.analyze_ip(ip)
        return analysis.reputation_score if analysis else None
    
    async def is_ip_malicious(self, ip: str) -> bool:
        """Verifica si una IP es maliciosa."""
        analysis = await self.analyze_ip(ip)
        return analysis.is_malicious if analysis else False
    
    async def get_ip_country(self, ip: str) -> Optional[str]:
        """Obtiene país de una IP."""
        analysis = await self.analyze_ip(ip)
        return analysis.country if analysis else None
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Obtiene resumen de análisis realizados."""
        return {
            'metrics': self.metrics,
            'cache_size': len(self.analysis_cache),
            'tor_nodes_known': len(self.tor_exit_nodes),
            'vpn_ranges_known': len(self.known_vpn_ranges),
            'malicious_asns_known': len(self.malicious_asns),
            'last_analysis': datetime.now().isoformat()
        }
    
    def cleanup_old_cache(self):
        """Limpia entradas antiguas del caché."""
        current_time = datetime.now()
        old_entries = []
        
        for ip, analysis in self.analysis_cache.items():
            cache_age = current_time - analysis.analysis_timestamp
            if cache_age.total_seconds() > (self.cache_hours * 3600):
                old_entries.append(ip)
        
        for ip in old_entries:
            del self.analysis_cache[ip]
        
        if old_entries:
            self.logger.info(f"🧹 Limpiadas {len(old_entries)} entradas del caché IP")


# ==================== TESTING ====================

def main():
    """Función de testing del IPAnalyzer."""
    import asyncio
    
    async def test_ip_analyzer():
        """Test del analizador de IPs."""
        print("🧪 Testing IP Analyzer...")
        
        # Configuración de prueba
        config = {
            'threat_intelligence': {
                'enable_geolocation': True,
                'reputation_cache_hours': 24
            }
        }
        
        # Crear analizador
        analyzer = IPAnalyzer(config)
        
        # Test inicialización
        success = await analyzer.initialize()
        print(f"✅ Inicialización: {'OK' if success else 'FALLO'}")
        
        if success:
            # Test IPs de prueba
            test_ips = [
                '185.220.100.240',  # Tor exit node
                '8.8.8.8',         # Google DNS
                '94.102.49.190',   # Sospechosa
                '192.168.1.1',     # IP privada
                '1.1.1.1'          # Cloudflare DNS
            ]
            
            for test_ip in test_ips:
                print(f"\n🔍 Analizando IP: {test_ip}")
                
                # Análisis completo
                result = await analyzer.analyze_ip(test_ip)
                if result:
                    print(f"   País: {result.country}")
                    print(f"   ISP: {result.isp}")
                    print(f"   Reputación: {result.reputation_score:.3f}")
                    print(f"   Tor: {result.is_tor}")
                    print(f"   VPN: {result.is_vpn}")
                    print(f"   Maliciosa: {result.is_malicious}")
                    if result.threat_types:
                        print(f"   Amenazas: {', '.join(result.threat_types)}")
                
                # Tests específicos
                reputation = await analyzer.get_ip_reputation(test_ip)
                is_malicious = await analyzer.is_ip_malicious(test_ip)
                country = await analyzer.get_ip_country(test_ip)
                
                print(f"   API - Reputación: {reputation:.3f if reputation else 'N/A'}")
                print(f"   API - Maliciosa: {is_malicious}")
                print(f"   API - País: {country or 'Desconocido'}")
            
            # Test resumen
            print(f"\n📊 Resumen de análisis:")
            summary = analyzer.get_analysis_summary()
            print(f"   IPs analizadas: {summary['metrics']['ips_analyzed']}")
            print(f"   Nodos Tor detectados: {summary['metrics']['tor_nodes_detected']}")
            print(f"   VPNs detectadas: {summary['metrics']['vpn_connections_detected']}")
            print(f"   IPs maliciosas: {summary['metrics']['malicious_ips_detected']}")
            print(f"   Cache size: {summary['cache_size']}")
        
        print("🏁 Test completado")
    
    # Ejecutar test
    asyncio.run(test_ip_analyzer())


if __name__ == "__main__":
    main()