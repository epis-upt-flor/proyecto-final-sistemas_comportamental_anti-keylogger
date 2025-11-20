# 🌐 TDD #2: Suspicious Port Detection

## 📋 Descripción del Test

**Funcionalidad**: Detectar conexiones de red a puertos sospechosos usados por malware
**Método TDD**: `NetworkDetector.analyze_port_usage(network_data)`
**Prioridad**: 🏆 #2 - Detecta exfiltración de datos robados

## 🚨 Puertos Sospechosos vs Legítimos

### Puertos de Alto Riesgo (Score: 0.9)
- `1337` - Leet speak, común en hacking tools
- `4444` - Metasploit default handler
- `5555` - Backdoors comunes
- `31337` - Elite hacker port
- `6667` - IRC bots para C&C

### Puertos de Medio Riesgo (Score: 0.5)  
- `8080` - Proxy alternativo (puede ser legítimo)
- `9999` - Desarrollo/testing (sospechoso en producción)
- `1234` - Puertos genéricos de malware

### Puertos Legítimos (Score: 0.1)
- `80` - HTTP estándar
- `443` - HTTPS seguro
- `53` - DNS
- `3306` - MySQL database
- `5432` - PostgreSQL database

## 🔄 Ciclo TDD Aplicado

### FASE RED (Test que falla)
```python
def test_suspicious_port_detection():
    network_data = {
        'connections': [
            {'remote_port': 4444, 'state': 'ESTABLISHED'},
            {'remote_port': 1337, 'state': 'ESTABLISHED'}
        ]
    }
    
    # Esta función NO EXISTE aún - debe fallar
    result = NetworkDetector.analyze_port_usage(network_data)
    
    assert result['is_suspicious'] is True
    assert result['risk_score'] >= 0.8
    assert len(result['suspicious_ports']) == 2
```

### FASE GREEN (Código mínimo)
Lista básica de puertos sospechosos y clasificación simple.

### FASE REFACTOR (Mejorar diseño)
- Context awareness (hora, frecuencia)
- Geo-IP analysis 
- Behavioral patterns
- Machine learning scoring

## 🎯 Casos de Prueba

1. **Conexión Maliciosa**: Puerto 4444 → Alto riesgo
2. **Tráfico Legítimo**: Puerto 443 → Bajo riesgo
3. **Múltiples Puertos**: Combinación → Score agregado
4. **Patrones Temporales**: Beaconing detection

## 📊 Criterios de Éxito

- ✅ Detecta puertos de malware conocidos
- ✅ No bloquea tráfico legítimo (HTTP/HTTPS)
- ✅ Identifica patrones de exfiltración
- ✅ Performance: análisis en tiempo real
- ✅ Configurable: whitelist/blacklist personalizable

## 🔗 Integración con el Proyecto

- **Archivo a crear**: `plugins/monitors/network_monitor/network_detector.py`
- **Método a crear**: `analyze_port_usage()`
- **Eventos**: Publicar `suspicious_network_activity`
- **Configuración**: Lista de puertos por categoría

---

**🌐 IMPORTANCIA**: Detecta cuando keyloggers envían datos robados a servidores de atacantes.