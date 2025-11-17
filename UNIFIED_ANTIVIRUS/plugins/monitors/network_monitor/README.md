# 🌐 Network Monitor Plugin

## Descripción General

Plugin de monitoreo continuo del tráfico de red que captura y analiza conexiones, flujos de datos y patrones de comunicación en tiempo real para detectar actividad maliciosa relacionada con keyloggers y malware.

## 🎯 Funcionalidades Principales

### ✅ **Monitoreo de Conexiones**
- **Nuevas conexiones**: Detección instantánea de conexiones TCP/UDP
- **Conexiones terminadas**: Seguimiento de conexiones cerradas
- **Estados de conexión**: Monitoreo de estados (ESTABLISHED, LISTEN, etc.)
- **Flujos de datos**: Análisis de cantidad y dirección de datos

### 📊 **Análisis de Tráfico**
- **Patrones de exfiltración**: Detección de transferencias sospechosas de datos
- **Comunicaciones C&C**: Identificación de conexiones de comando y control
- **Beacons periódicos**: Detección de comunicaciones regulares automatizadas
- **Protocolos no estándar**: Análisis de uso anómalo de protocolos

### 🔍 **Inteligencia de Red**
- **Geolocalización**: Ubicación de IPs de destino
- **Reputación de IPs**: Análisis contra listas de IPs maliciosas
- **Análisis de dominios**: Detección de dominios sospechosos y DGA
- **Análisis de puertos**: Identificación de servicios y puertos inusuales

## 📁 Archivos del Plugin

```
network_monitor/
├── plugin.py          # NetworkMonitorPlugin principal
├── test_plugin.py     # Tests unitarios
├── __init__.py        # Auto-registro del plugin
└── README.md         # Esta documentación
```

## ⚙️ Configuración

### Configuración Típica
```json
{
  "monitor_config": {
    "capture_interface": "any",
    "capture_timeout": 1000,
    "buffer_size": 65536,
    "promiscuous_mode": false,
    "real_time_analysis": true
  },
  "traffic_analysis": {
    "min_connection_duration": 1.0,
    "suspicious_upload_ratio": 0.8,
    "beacon_tolerance": 0.3,
    "c2_detection_threshold": 0.7
  },
  "filtering": {
    "monitor_tcp": true,
    "monitor_udp": true,
    "monitor_icmp": false,
    "ignore_local_traffic": false,
    "port_whitelist": [80, 443, 53, 22],
    "ignore_broadcasts": true
  },
  "threat_intelligence": {
    "enable_ip_lookup": true,
    "malicious_ips_file": "threat_intel/malicious_ips.txt",
    "check_domain_reputation": true,
    "max_lookup_threads": 5
  }
}
```

### Interfaces de Red
- **`any`**: Monitorea todas las interfaces (recomendado)
- **`ethernet`**: Solo interfaces Ethernet
- **`wifi`**: Solo interfaces Wi-Fi
- **Interface específica**: ej. "eth0", "wlan0"

## 🔌 **Eventos del Sistema**

### **Eventos Publicados:**
- `connection_established` - Nueva conexión detectada
- `connection_terminated` - Conexión terminada
- `suspicious_traffic_detected` - Tráfico sospechoso identificado
- `c2_communication_detected` - Comunicación C&C detectada
- `data_exfiltration_detected` - Posible exfiltración de datos
- `beacon_pattern_detected` - Patrón de beacon identificado
- `malicious_ip_contacted` - Contacto con IP maliciosa

### **Estructura de Eventos:**
```python
{
  "event_type": "c2_communication_detected",
  "timestamp": "2024-11-08T15:30:45",
  "connection_info": {
    "local_ip": "192.168.1.100",
    "local_port": 54321,
    "remote_ip": "203.0.113.45",
    "remote_port": 8080,
    "protocol": "TCP",
    "state": "ESTABLISHED",
    "pid": 1234,
    "process_name": "suspicious.exe"
  },
  "traffic_analysis": {
    "bytes_sent": 2048,
    "bytes_received": 512,
    "packets_sent": 15,
    "packets_received": 8,
    "upload_ratio": 0.8,
    "duration_seconds": 45.2
  },
  "threat_indicators": {
    "ip_reputation": "malicious",
    "domain_reputation": "suspicious", 
    "beacon_pattern": true,
    "c2_probability": 0.85,
    "geolocation": "Unknown/Tor"
  }
}
```

## 🚀 **Uso del Plugin**

### Inicialización Automática
```python
# El plugin se registra automáticamente
# Se activa con la categoría 'monitors'
engine.activate_category('monitors')
```

### Configuración Manual
```python
# Crear instancia del monitor
network_monitor = NetworkMonitorPlugin()

# Configurar interface y filtros
config = {
    "capture_interface": "any",
    "monitor_tcp": True,
    "real_time_analysis": True
}
network_monitor.configure(config)

# Inicializar y comenzar monitoreo
if network_monitor.initialize():
    network_monitor.start()
```

## 📈 **Métricas y Estadísticas**

### Métricas del Monitor
```python
monitor_stats = {
    'connections_monitored': 0,      # Conexiones totales monitoreadas
    'active_connections': 0,         # Conexiones actualmente activas  
    'suspicious_connections': 0,     # Conexiones sospechosas detectadas
    'c2_communications': 0,          # Comunicaciones C&C detectadas
    'data_exfiltrated_mb': 0.0,     # Datos potencialmente exfiltrados
    'beacon_patterns_found': 0,      # Patrones de beacon encontrados
    'malicious_ips_contacted': 0,    # IPs maliciosas contactadas
    'uptime_hours': 0.0             # Tiempo de funcionamiento
}
```

### Performance del Monitor
- **Latencia de captura**: < 10ms para nuevas conexiones
- **Throughput**: >10,000 paquetes/segundo
- **Uso de memoria**: 50-100MB dependiendo del tráfico
- **Impacto en CPU**: 2-5% en tráfico normal, 5-10% en picos

## 🔬 **Análisis Especializado**

### Detección de Patrones C&C
```python
c2_indicators = {
    'beacon_patterns': {
        'regular_intervals': [60, 300, 600, 3600],  # segundos
        'small_payloads': '<1KB typical',
        'encrypted_traffic': 'high entropy',
        'persistent_connections': 'long duration'
    },
    'communication_patterns': {
        'heartbeat': 'regular small packets',
        'command_fetch': 'periodic downloads',
        'data_upload': 'bulk uploads after activity',
        'keep_alive': 'maintain connection'
    }
}
```

### Análisis de Exfiltración
- **Ratio upload/download anómalo**: >80% uploads
- **Transferencias frecuentes**: Múltiples uploads pequeños
- **Destinos múltiples**: Datos enviados a varias IPs
- **Horarios inusuales**: Actividad fuera de horas laborales
- **Patrones de burst**: Ráfagas súbitas de transferencias

### Detección de Túneles
```python
tunnel_detection = {
    'dns_tunneling': {
        'large_queries': '>253 characters',
        'txt_records': 'unusual TXT record usage',
        'frequency': 'excessive DNS queries',
        'entropy': 'high entropy in subdomain'
    },
    'http_tunneling': {
        'unusual_headers': 'custom HTTP headers',
        'large_posts': 'unusually large POST data',
        'regular_timing': 'predictable intervals',
        'encoded_data': 'base64/hex encoded payloads'
    }
}
```

## 🛡️ **Inteligencia de Amenazas**

### Fuentes de Threat Intelligence
```python
threat_sources = {
    'ip_reputation': [
        'malware_ips.txt',          # IPs de malware conocidas
        'botnet_ips.txt',           # IPs de botnets activas
        'tor_exit_nodes.txt',       # Nodos de salida Tor
        'c2_servers.txt'            # Servidores C&C conocidos
    ],
    'domain_reputation': [
        'malicious_domains.txt',    # Dominios maliciosos
        'dga_domains.txt',          # Dominios generados por DGA
        'phishing_domains.txt',     # Dominios de phishing
        'suspicious_tlds.txt'       # TLDs sospechosos
    ]
}
```

### Análisis Geográfico
- **Países de riesgo alto**: Conexiones desde regiones con alta actividad maliciosa
- **Servicios VPN/Proxy**: Detección de conexiones a través de VPNs
- **Nodos Tor**: Identificación de tráfico Tor
- **ASN analysis**: Análisis de proveedores de internet sospechosos

## 🛠️ **Desarrollo y Testing**

### Testing del Plugin
```bash
# Ejecutar tests unitarios
python test_plugin.py

# Test manual del plugin
cd plugins/monitors/network_monitor  
python plugin.py --test

# Generar tráfico de prueba
python plugin.py --generate-traffic

# Simular comunicaciones C&C
python plugin.py --simulate-c2
```

### Herramientas de Análisis
```python
# Análisis de una conexión específica
network_monitor.analyze_connection("192.168.1.100", 54321)

# Verificar patrones de beacon
network_monitor.check_beacon_pattern(connection_history)

# Análisis de reputación de IP
reputation = network_monitor.check_ip_reputation("203.0.113.45")

# Estadísticas en tiempo real
stats = network_monitor.get_statistics()
print(f"Active connections: {stats['active_connections']}")
```

## 🔧 **Troubleshooting**

### Problemas Comunes

#### **No Captura Tráfico**
```
Causa: Permisos insuficientes o interface incorrecta
Solución:
- Ejecutar como administrador
- Verificar interface de red con: python plugin.py --list-interfaces
- Comprobar que la interface esté activa
```

#### **Alto Uso de CPU/Memoria**
```
Causa: Análisis en tiempo real de mucho tráfico
Solución:
- Reducir real_time_analysis para análisis batch
- Aplicar más filtros (port_whitelist, ignore_local_traffic)
- Aumentar capture_timeout para reducir frecuencia
```

#### **Muchos Falsos Positivos**
```
Causa: Umbrales de detección muy sensibles
Solución:
- Aumentar c2_detection_threshold
- Refinar suspicious_upload_ratio
- Agregar IPs legítimas a whitelist
- Ajustar beacon_tolerance
```

### Optimización de Performance
- **Filtrado a nivel de kernel**: Usar BPF filters para filtrar temprano
- **Análisis asíncrono**: Procesar paquetes en threads separados  
- **Muestreo de tráfico**: Analizar solo una muestra del tráfico total
- **Cache de lookups**: Cachear resultados de reputation/geolocation

## 📚 **Integración con Detectores**

### Flujo de Análisis de Red
1. **Network Monitor** captura nueva conexión
2. **Análisis básico**: Extrae metadatos de conexión
3. **Threat Intelligence**: Verifica reputación de IP/dominio
4. **Pattern Analysis**: Busca patrones de C&C, exfiltración, etc.
5. **Event Bus**: Distribuye eventos según hallazgos
6. **Detectores especializados** procesan:
   - **Network Detector**: Análisis avanzado de patrones
   - **ML Detector**: Predicción basada en características de red
   - **Behavior Detector**: Correlación con actividad de procesos

### Correlación Multi-Modal
```python
# Correlación entre network y process monitor
correlation_analysis = {
    'network_event': network_event,
    'related_process': process_info,
    'temporal_correlation': time_diff < 30,    # 30 segundos
    'behavioral_correlation': same_pid,
    'risk_amplification': combined_risk_score
}
```

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[👁️ Sistema de Monitores](../README.md)** - Documentación de monitores
- **[🖥️ Process Monitor](../process_monitor/README.md)** - Monitor de procesos
- **[📁 File Monitor](../file_monitor/README.md)** - Monitor del sistema de archivos
- **[🌐 Network Detector](../../detectors/network_detector/README.md)** - Análisis avanzado de red
- **[🤖 ML Detector](../../detectors/ml_detector/README.md)** - Machine learning para red
- **[🛡️ Threat Intelligence](../../../threat_intel/README.md)** - Inteligencia de amenazas
- **[📊 Core Engine](../../../core/README.md)** - Event Bus y motor principal
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Monitoreo Continuo de Red Avanzado**