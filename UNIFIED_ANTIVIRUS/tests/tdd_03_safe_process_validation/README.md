# ✅ TDD #3: Safe Process Validation

## 📋 Descripción del Test

**Funcionalidad**: Validar que procesos legítimos NO sean detectados como amenazas
**Método TDD**: `ProcessValidator.is_process_safe(process_data)`  
**Prioridad**: 🏆 #3 - Crítico para UX (evita falsos positivos)

## 🛡️ Procesos Seguros vs Sospechosos

### Procesos Legítimos (Whitelist)
- `notepad.exe` - Editor de texto de Windows
- `chrome.exe` - Navegador Google Chrome
- `firefox.exe` - Navegador Mozilla Firefox  
- `explorer.exe` - Windows Explorer
- `winword.exe` - Microsoft Word
- `excel.exe` - Microsoft Excel
- `steam.exe` - Plataforma Steam gaming

### Procesos Sospechosos (Blacklist)
- `keylogger.exe` - Nombre obvio de keylogger
- `stealer.exe` - Password stealer
- `backdoor.exe` - Backdoor malware
- `rootkit.exe` - Rootkit malware
- Procesos con nombres aleatorios: `x1b2c3.exe`

### Criterios de Seguridad
- **Firma digital válida** (Microsoft, Google, etc.)
- **Ubicación legítima** (Program Files, Windows)
- **Reputación conocida** (whitelist curada)
- **Comportamiento normal** (uso CPU/memoria)

## 🔄 Ciclo TDD Aplicado

### FASE RED (Test que falla)
```python
def test_notepad_should_not_be_detected_as_threat():
    process_data = {
        'name': 'notepad.exe',
        'path': 'C:\\Windows\\System32\\notepad.exe'
    }
    
    # Esta función NO EXISTE aún - debe fallar  
    result = ProcessValidator.is_process_safe(process_data)
    
    assert result['is_safe'] is True
    assert result['confidence'] >= 0.9
    assert result['threat_score'] == 0.0
```

### FASE GREEN (Código mínimo)
Whitelist básica de procesos conocidos como seguros.

### FASE REFACTOR (Mejorar diseño)
- Verificación de firmas digitales
- Análisis de ubicación del archivo
- Sistema de reputación dinámico
- Machine learning para nuevos procesos

## 🎯 Casos de Prueba

1. **Proceso Conocido**: notepad.exe → Seguro
2. **Navegador Popular**: chrome.exe → Seguro  
3. **Malware Conocido**: keylogger.exe → Peligroso
4. **Proceso Desconocido**: random123.exe → Investigar
5. **Ubicación Sospechosa**: notepad.exe en Temp → Sospechoso

## 📊 Criterios de Éxito

- ✅ 0% falsos positivos en software popular
- ✅ Detección correcta de malware conocido
- ✅ Manejo elegante de procesos desconocidos
- ✅ Performance: <10ms por validación
- ✅ Actualizable: whitelist/blacklist configurable

## 🔗 Integración con el Proyecto

- **Archivo a crear**: `plugins/validators/process_validator.py`
- **Método a crear**: `is_process_safe()`
- **Datos**: Lista de procesos seguros conocidos
- **Configuración**: Whitelist personalizable por usuario

---

**👤 UX CRÍTICO**: Evita que el antivirus moleste al usuario con falsas alarmas de software legítimo.