# 🎯 TDD #1: API Hooking Detection

## 📋 Descripción del Test

**Funcionalidad**: Detectar APIs sospechosas utilizadas por keyloggers reales
**Método TDD**: `KeyloggerDetector.analyze_api_usage(process_data)`
**Prioridad**: 🏆 #1 - Máxima relevancia para el antivirus

## 🦠 APIs Críticas de Keyloggers

### APIs de Alto Riesgo (Score: 0.9)
- `SetWindowsHookEx` - Hook principal para interceptar teclas
- `GetAsyncKeyState` - Leer estado actual de teclas
- `GetForegroundWindow` - Saber qué ventana está activa

### APIs de Medio Riesgo (Score: 0.6)
- `CreateFileA/W` - Crear archivos de log
- `WriteFile` - Escribir datos capturados
- `GetSystemTime` - Timestamp para logs

### APIs Legítimas (Score: 0.1)
- `CreateWindow` - Crear ventanas normales
- `ShowWindow` - Mostrar ventanas
- `GetMessage` - Loop de mensajes normal

## 🔄 Ciclo TDD Aplicado

### FASE RED (Test que falla)
```python
def test_detect_hooking_apis_should_return_high_risk():
    process_data = {
        'name': 'suspicious_keylogger.exe',
        'apis_called': ['SetWindowsHookEx', 'GetAsyncKeyState']
    }
    
    # Esta función NO EXISTE aún - debe fallar
    result = KeyloggerDetector.analyze_api_usage(process_data)
    
    assert result['is_suspicious'] is True
    assert result['risk_score'] >= 0.8
    assert 'api_hooking' in result['threat_indicators']
```

### FASE GREEN (Código mínimo)
Implementar función básica que solo detecte estas APIs específicas.

### FASE REFACTOR (Mejorar diseño)
- Algoritmo de scoring sofisticado
- Ponderación por combinaciones de APIs
- Cache de resultados para performance

## 🎯 Casos de Prueba

1. **Keylogger Real**: APIs de hooking → Alto riesgo
2. **Logger Básico**: APIs de archivo → Medio riesgo  
3. **Aplicación Legítima**: APIs normales → Bajo riesgo
4. **Combinaciones**: Múltiples APIs → Score acumulativo

## 📊 Criterios de Éxito

- ✅ Detecta keyloggers reales (APIs críticas)
- ✅ No genera falsos positivos en software legítimo
- ✅ Score proporcional al nivel de amenaza
- ✅ Performance: <50ms por análisis
- ✅ Cobertura: 100% de APIs conocidas

## 🔗 Integración con el Proyecto

- **Archivo base**: `plugins/detectors/keylogger_detector/keylogger_detector.py`
- **Método a crear**: `analyze_api_usage()`
- **Eventos**: Publicar `threat_detected` en caso positivo
- **Configuración**: Umbrales ajustables por sensibilidad

---

**🚨 CRÍTICO**: Este es el test más importante porque detecta la técnica principal que usan los keyloggers reales para capturar teclas.