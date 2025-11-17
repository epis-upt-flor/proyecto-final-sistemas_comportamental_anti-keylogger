# 🛡️ Threat Intelligence - Inteligencia de Amenazas

## Descripción General

Directorio centralizado que contiene bases de datos de inteligencia de amenazas para el sistema UNIFIED_ANTIVIRUS. Proporciona feeds actualizados de indicadores de compromiso (IOCs) para mejorar la detección proactiva de amenazas.

## 🎯 Tipos de Intelligence

### 🌐 **Intelligence de Red**
- **`malicious_ips.txt`** - IPs maliciosas conocidas
- **`domains.txt`** - Dominios sospechosos y maliciosos

### 📊 **Fuentes de Datos**
- **Feeds públicos** de threat intelligence
- **Análisis interno** de amenazas detectadas
- **Sharing communities** de ciberseguridad
- **Honeypots** y sistemas de detección

## 📁 Estructura de Archivos

```
threat_intel/
├── malicious_ips.txt    # Base de datos de IPs maliciosas
├── domains.txt          # Dominios sospechosos y DGA
└── README.md           # Esta documentación
```

## 🌐 **malicious_ips.txt** - IPs Maliciosas

### Descripción
Base de datos de direcciones IP conocidas por actividad maliciosa, incluyendo:
- **Servidores C&C**: Command & Control de botnets
- **IPs de malware**: Direcciones usadas por malware conocido
- **Nodos Tor**: Exit nodes de la red Tor
- **Proxies maliciosos**: Servicios proxy comprometidos
- **Scanning IPs**: Direcciones que realizan escaneos masivos

### Formato
```
# Comentarios con información adicional
192.0.2.1    # Botnet Zeus C&C server
203.0.113.45 # Keylogger exfiltration server  
198.51.100.3 # Tor exit node (suspicious activity)
192.0.2.100  # Malware dropper distribution
```

### Categorías de IPs
```
# Command & Control Servers
192.0.2.1     # Zeus botnet
203.0.113.2   # Emotet C&C
198.51.100.5  # TrickBot infrastructure

# Keylogger Infrastructure  
203.0.113.45  # Data exfiltration server
192.0.2.200   # Keylogger command server
198.51.100.99 # Stolen data collection

# Malware Distribution
192.0.2.150   # Malware payload server
203.0.113.80  # Drive-by download site
198.51.100.25 # Exploit kit landing

# Scanning & Reconnaissance
192.0.2.50    # Port scanner source
203.0.113.15  # Vulnerability scanner
198.51.100.10 # Network reconnaissance
```

### Uso en el Sistema
```python
# Network Detector usa estas IPs para análisis
def check_ip_reputation(ip_address):
    with open('threat_intel/malicious_ips.txt', 'r') as f:
        malicious_ips = f.read().splitlines()
        
    for line in malicious_ips:
        if line.startswith('#'):
            continue
        ip = line.split('#')[0].strip()
        if ip == ip_address:
            return {'status': 'malicious', 'source': 'threat_intel'}
    return {'status': 'unknown'}
```

## 📋 **domains.txt** - Dominios Sospechosos

### Descripción
Base de datos de dominios maliciosos y sospechosos, incluyendo:
- **Dominios de phishing**: Sitios de suplantación
- **C&C domains**: Dominios de comando y control
- **DGA domains**: Dominios generados algorítmicamente
- **Malware hosting**: Sitios que distribuyen malware
- **Typosquatting**: Dominios similares a sitios legítimos

### Formato
```
# Comentarios descriptivos
evil-site.com           # Phishing site targeting banks
c2server.malware.net    # Command & control for keylogger
randomstring123.tk      # DGA domain from Conficker
fake-update.com         # Fake software update site
```

### Categorías de Dominios
```
# Phishing & Social Engineering
fake-bank.com          # Banking phishing
security-alert.net     # Fake security warnings
update-required.org    # Software update scams

# Command & Control
c2.botnet-alpha.com    # Botnet C&C
cmd.malware123.net     # Keylogger commands
control.evil.tk        # General malware C&C

# DGA (Domain Generation Algorithm)
abcdef123456.com       # Conficker DGA
xyzabc789012.net       # Sality DGA
random123abc.tk        # Generic DGA pattern

# Malware Distribution
download-codec.com     # Fake codec downloads
free-software.evil     # Trojanized software
crack-tools.malware    # Cracking tools with malware
```

### Uso en el Sistema
```python
# Network Detector verifica dominios
def check_domain_reputation(domain):
    with open('threat_intel/domains.txt', 'r') as f:
        malicious_domains = f.read().splitlines()
        
    for line in malicious_domains:
        if line.startswith('#'):
            continue
        dom = line.split('#')[0].strip()
        if domain.endswith(dom) or dom in domain:
            return {'status': 'malicious', 'category': 'known_bad'}
    return {'status': 'unknown'}
```

## 🔄 **Actualización de Intelligence**

### Fuentes de Datos
```python
# Feeds de threat intelligence
threat_feeds = {
    'public_feeds': [
        'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'https://hosts-file.net/grm.txt',
        'https://someonewhocares.org/hosts/zero/hosts'
    ],
    'commercial_feeds': [
        'VirusTotal API',
        'AlienVault OTX', 
        'ThreatCrowd API',
        'URLVoid API'
    ],
    'internal_sources': [
        'honeypot_logs',
        'detected_threats',
        'sandbox_analysis',
        'user_reports'
    ]
}
```

### Proceso de Actualización
1. **Descarga**: Obtener feeds de fuentes externas
2. **Validación**: Verificar formato y calidad de datos
3. **Deduplicación**: Eliminar entradas duplicadas
4. **Categorización**: Clasificar por tipo de amenaza
5. **Merging**: Combinar con intelligence existente
6. **Testing**: Validar que no rompa detección legítima
7. **Deployment**: Activar nueva intelligence en producción

### Automatización
```python
# Script de actualización automática
def update_threat_intelligence():
    # Descargar feeds externos
    new_ips = download_ip_feeds()
    new_domains = download_domain_feeds()
    
    # Validar y filtrar
    validated_ips = validate_ip_list(new_ips)
    validated_domains = validate_domain_list(new_domains)
    
    # Merge con datos existentes
    merge_intelligence_data(validated_ips, validated_domains)
    
    # Recargar en detectores
    reload_network_detector_intelligence()
    
    # Log de actualización
    log_intelligence_update(len(validated_ips), len(validated_domains))
```

## 📊 **Métricas de Intelligence**

### Estadísticas de Uso
```python
intelligence_stats = {
    'malicious_ips_count': 0,      # Total de IPs en base
    'domains_count': 0,            # Total de dominios
    'daily_hits': 0,               # Coincidencias diarias
    'false_positive_rate': 0.0,    # Tasa de falsos positivos
    'coverage_improvement': 0.0,   # Mejora en detección
    'last_update': None,           # Última actualización
    'feed_sources_active': 0       # Fuentes activas
}
```

### Análisis de Efectividad
- **Hit rate**: % de tráfico que coincide con intelligence
- **Detection improvement**: Amenazas adicionales detectadas
- **False positive rate**: Tráfico legítimo marcado erróneamente
- **Coverage gaps**: Amenazas no cubiertas por intelligence

## 🔍 **Integración con Detectores**

### Network Detector
```python
# Verificación en tiempo real
def analyze_connection(src_ip, dst_ip, domain=None):
    threat_level = 'low'
    
    # Check IP reputation
    if dst_ip in malicious_ips:
        threat_level = 'high'
        log_threat_detected('malicious_ip', dst_ip)
    
    # Check domain reputation  
    if domain and domain in malicious_domains:
        threat_level = 'high'
        log_threat_detected('malicious_domain', domain)
    
    return threat_level
```

### Behavior Detector
```python
# Correlación con comportamiento
def correlate_with_intelligence(process_info, network_connections):
    risk_score = 0
    
    for conn in network_connections:
        if conn['dst_ip'] in malicious_ips:
            risk_score += 0.8  # Alta sospecha
        if conn.get('domain') in malicious_domains:
            risk_score += 0.9  # Muy alta sospecha
    
    return min(risk_score, 1.0)
```

## 🛡️ **Calidad de Datos**

### Validación de Entradas
```python
def validate_ip_entry(ip_line):
    # Validar formato IP
    ip = ip_line.split('#')[0].strip()
    if not is_valid_ip(ip):
        return False
    
    # Evitar IPs privadas/reservadas
    if is_private_ip(ip) or is_reserved_ip(ip):
        return False
    
    return True

def validate_domain_entry(domain_line):
    # Validar formato de dominio
    domain = domain_line.split('#')[0].strip()
    if not is_valid_domain(domain):
        return False
    
    # Evitar dominios legítimos conocidos
    if domain in legitimate_domains_whitelist:
        return False
    
    return True
```

### Control de Calidad
- **Whitelisting**: Excluir IPs/dominios legítimos conocidos
- **Geo-filtering**: Filtrar por ubicación geográfica
- **Age-based filtering**: Priorizar intelligence reciente
- **Source reliability**: Ponderar por confiabilidad de fuente

## 🚀 **Herramientas de Análisis**

### Consultas de Intelligence
```bash
# Top IPs más detectadas
grep "malicious_ip" ../logs/network_detector.log | awk '{print $NF}' | sort | uniq -c | sort -nr | head -10

# Dominios bloqueados hoy
grep "$(date +%Y-%m-%d)" ../logs/network_detector.log | grep "malicious_domain" | wc -l

# Efectividad de intelligence
grep "threat_intel" ../logs/*.log | grep "$(date +%Y-%m-%d)" | wc -l
```

### Reportes Automáticos
```python
def generate_intelligence_report():
    return {
        'period': 'last_24_hours',
        'total_queries': count_intelligence_queries(),
        'hits': count_intelligence_hits(), 
        'new_threats_blocked': count_new_threats(),
        'top_malicious_ips': get_top_malicious_ips(10),
        'top_malicious_domains': get_top_malicious_domains(10),
        'recommendation': get_intelligence_recommendations()
    }
```

## 🔧 **Mantenimiento**

### Limpieza Periódica
```python
# Limpieza automática de intelligence obsoleta
def cleanup_old_intelligence():
    # Eliminar entradas antiguas sin hits
    remove_unused_entries(days=30)
    
    # Eliminar duplicados
    deduplicate_intelligence_data()
    
    # Verificar IPs/dominios caídos
    validate_active_threats()
    
    # Compactar archivos
    compress_intelligence_files()
```

### Backup y Recovery
- **Daily backup**: Copia diaria de archivos de intelligence
- **Versioning**: Control de versiones de bases de datos
- **Rollback**: Capacidad de revertir actualizaciones problemáticas
- **Disaster recovery**: Recuperación desde fuentes externas

## 🔗 **Enlaces Relacionados**

### Detectores que Usan Intelligence  
- **[📋 README Principal](../README.md)** - Navegación general del proyecto
- **[🌐 Network Detector](../plugins/detectors/network_detector/README.md)** - Principal usuario de threat intelligence
- **[🌐 Network Monitor](../plugins/monitors/network_monitor/README.md)** - Monitoreo que usa intelligence
- **[🎯 Behavior Detector](../plugins/detectors/behavior_detector/README.md)** - Correlación con comportamiento
- **[🤖 ML Detector](../plugins/detectors/ml_detector/README.md)** - Features enriquecidas con intelligence

### Sistema de Soporte
- **[📊 Core Engine](../core/README.md)** - Motor que coordina uso de intelligence
- **[⚙️ Configuración](../config/README.md)** - Configuración de threat intelligence
- **[📝 Logs](../logs/README.md)** - Logs de uso de intelligence
- **[🛠️ Utils](../utils/README.md)** - Utilidades para procesamiento de datos
- **[🔌 Sistema de Plugins](../plugins/README.md)** - Arquitectura de integración

### Herramientas de Análisis
- **Network Analyzer** - Análisis de patrones de red
- **IP Reputation** - Sistema de reputación de IPs  
- **Domain Analysis** - Análisis de dominios y DNS
- **Threat Correlation** - Correlación de indicadores

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../README.md) - Sistema de Inteligencia de Amenazas Proactiva**

**Fuentes**: Feeds públicos + Análisis interno  
**Actualización**: Diaria automática  
**Cobertura**: IPs maliciosas + Dominios sospechosos