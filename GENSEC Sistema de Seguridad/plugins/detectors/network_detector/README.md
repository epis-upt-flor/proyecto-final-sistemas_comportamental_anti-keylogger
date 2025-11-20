# 🌐 Network Detector Plugin

Plugin especializado en **análisis de patrones de red** para detectar comunicaciones maliciosas típicas de keyloggers.

## 🎯 **Funcionalidades**

### ✅ **Análisis de Tráfico**
- **Patrones C&C** - Detección de comunicaciones con servidores de comando y control
- **Exfiltración de datos** - Identificación de transferencias sospechosas de información
- **Beacons periódicos** - Detección de comunicaciones regulares automatizadas
- **Protocolos no estándar** - Análisis de uso anómalo de protocolos

### 🔍 **Inteligencia de Amenazas**
- **IPs maliciosas** conocidas desde feeds de threat intelligence
- **Dominios sospechosos** y DGA (Domain Generation Algorithms)
- **Análisis de reputación** de direcciones IP
- **Geolocalización** y categorización de conexiones

### 📊 **Análisis Temporal**
- **Timeline de conexiones** por IP y proceso
- **Correlación temporal** de comunicaciones
- **Patrones de beacon** con análisis estadístico
- **Detección de túneles** DNS y HTTP

## 🏗️ **Patrones de Diseño**

### **Observer Pattern**
- Monitoreo continuo de conexiones de red
- Eventos publicados en tiempo real para nuevas amenazas

### **Strategy Pattern**
- Múltiples estrategias de análisis: C&C, exfiltración, beacons
- Algoritmos intercambiables según tipo de amenaza

### **Template Method Pattern**
- Proceso estándar de análisis de red
- Métodos especializados para cada tipo de detección

### **Chain of Responsibility**
- Cadena de analizadores especializados
- Cada analizador evalúa aspectos específicos del tráfico

## 📁 **Archivos del Plugin**

```
network_detector/
├── plugin.py              # NetworkDetectorPlugin principal
├── network_analyzer.py    # Motor de análisis de tráfico
├── threat_intelligence.py # Gestor de inteligencia de amenazas
├── pattern_detector.py    # Detectores de patrones específicos
├── ip_analyzer.py         # Análisis detallado de direcciones IP
├── config.json           # Configuración del plugin
├── __init__.py           # Auto-registro
└── README.md             # Esta documentación
```

## ⚙️ **Configuración**

```json
{
  "network_config": {
    "analysis_window_minutes": 10,
    "min_connections_for_pattern": 3,
    "beacon_tolerance": 0.3,
    "suspicious_upload_threshold": 1024,
    "c2_confidence_threshold": 0.7
  },
  "threat_intelligence": {
    "enable_ip_reputation": true,
    "enable_domain_analysis": true,
    "malicious_ips_file": "threat_intel/malicious_ips.txt",
    "suspicious_domains_file": "threat_intel/domains.txt"
  }
}
```

## 🔌 **Eventos del Sistema**

### **Eventos Suscritos:**
- `network_connection_established` - Nueva conexión detectada
- `network_data_transferred` - Transferencia de datos en curso
- `dns_query_made` - Consulta DNS realizada
- `scan_requested` - Solicitud de análisis de red

### **Eventos Publicados:**
- `c2_communication_detected` - Comunicación C&C identificada
- `data_exfiltration_detected` - Exfiltración de datos detectada
- `beacon_pattern_detected` - Patrón de beacon encontrado
- `malicious_domain_accessed` - Acceso a dominio malicioso

## 🚀 **Uso**

### **Activación automática:**
```python
# Se activa con categoría 'detectors'
engine.activate_category('detectors')
```

### **Análisis manual:**
```python
network_plugin = plugin_manager.create_plugin('network_detector')
threats = network_plugin.analyze_connections(network_data)
```

## 📈 **Métricas**

- **connections_analyzed**: Conexiones totales analizadas
- **c2_communications_detected**: Comunicaciones C&C detectadas  
- **data_exfiltration_detected**: Casos de exfiltración identificados
- **beacon_patterns_found**: Patrones de beacon encontrados
- **malicious_ips_blocked**: IPs maliciosas detectadas
- **suspicious_domains_flagged**: Dominios sospechosos marcados

## 🎛️ **Detectores Especializados**

### **C&C Communication Detector:**
- Beacons periódicos con intervalos regulares
- Comunicaciones encriptadas a IPs desconocidas
- Patrones de heartbeat y keep-alive
- Uso de puertos no estándar

### **Data Exfiltration Detector:**
- Uploads frecuentes de datos pequeños
- Ratio upload/download anómalo (>80% upload)
- Transferencias a múltiples destinos externos
- Encriptación de datos transferidos

### **DNS Tunnel Detector:**
- Consultas DNS excesivamente largas
- Subdominios con patrones de DGA
- Transferencias de datos via DNS TXT records
- Frecuencia anómala de consultas DNS

### **Protocol Anomaly Detector:**
- HTTP en puertos no estándar
- Protocolos encriptados custom
- Payloads con entropía alta (posible encriptación)
- Headers HTTP anómalos

## 🛡️ **Inteligencia de Amenazas**

### **Fuentes de Datos:**
- **Malware IPs** - IPs conocidas de C&C servers
- **Botnet Tracking** - Seguimiento de botnets activos  
- **DGA Domains** - Dominios generados algorítmicamente
- **IOC Feeds** - Indicadores de compromiso actualizados

### **Análisis de Reputación:**
```json
{
  "ip_reputation_sources": [
    "virustotal_api",
    "abuseipdb", 
    "malware_domains",
    "threat_crowd"
  ],
  "reputation_thresholds": {
    "malicious": 0.8,
    "suspicious": 0.6,
    "neutral": 0.4,
    "trusted": 0.2
  }
}
```

## 🧪 **Testing**

### **Test del plugin:**
```bash
cd plugins/detectors/network_detector
python plugin.py --test
```

### **Simulación de amenazas:**
```bash
python plugin.py --simulate-c2
python plugin.py --simulate-exfiltration
```

## 🔧 **Troubleshooting**

### **Falsos positivos:**
- Ajustar `c2_confidence_threshold` en configuración
- Agregar IPs legítimas a whitelist
- Revisar patrones de beacon demasiado sensibles

### **Rendimiento lento:**
- Reducir `analysis_window_minutes`
- Limitar `min_connections_for_pattern` 
- Deshabilitar análisis de reputación en tiempo real

### **Detecciones perdidas:**
- Verificar feeds de threat intelligence actualizados
- Revisar umbrales de detección muy altos
- Comprobar que eventos de red llegan correctamente

## 🔗 **Enlaces Relacionados**

- **[📋 README Principal](../../../README.md)** - Navegación general del proyecto
- **[🔌 Sistema de Plugins](../../README.md)** - Arquitectura de plugins
- **[🧠 Recursos Compartidos](../../shared/README.md)** - Motor de inteligencia unificado
- **[🌐 Monitor de Red](../../monitors/network_monitor/README.md)** - Monitor de tráfico de red
- **[🎯 Behavior Detector](../behavior_detector/README.md)** - Detector de comportamiento
- **[🤖 ML Detector](../ml_detector/README.md)** - Detector con machine learning
- **[⌨️ Keylogger Detector](../keylogger_detector/README.md)** - Detector especializado
- **[🛡️ Threat Intelligence](../../../threat_intel/README.md)** - Inteligencia de amenazas
- **[⚙️ Configuración](../../../config/README.md)** - Sistema de configuración
- **[📊 Core Engine](../../../core/README.md)** - Motor principal del sistema

---

**Desarrollado como parte del [UNIFIED_ANTIVIRUS](../../../README.md) - Sistema de Detección de Red Avanzada**