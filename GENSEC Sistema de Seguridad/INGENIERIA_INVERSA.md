# 🔍 Ingeniería Inversa: GENSEC Sistema de Seguridad

## 📌 Resumen Ejecutivo

Este documento presenta los resultados del análisis de ingeniería inversa del código fuente del proyecto "GENSEC Sistema de Seguridad", revelando **discrepancias significativas** entre la documentación oficial (que describe un "sistema antivirus") y la implementación real del código.

---

## 1. DESCRIPCIÓN REAL DEL SISTEMA

### ¿Qué es realmente este sistema según el código fuente?

**GENSEC** es un **framework de investigación académica para análisis comportamental de keyloggers** basado en Python, desarrollado como proyecto de curso de Sistemas Comportamentales en la Universidad Privada de Tacna (UPT).

### Componentes Principales

El sistema consta de:

1. **Motor de Plugins Modular** (`UnifiedAntivirusEngine`)
   - Gestión dinámica de plugins
   - Sistema de eventos desacoplado (Observer Pattern)
   - Arquitectura extensible basada en interfaces

2. **Detectores de Patrones de Keyloggers**
   - `KeyloggerDetector`: Detector especializado basado en análisis de malware real
   - `BehaviorDetector`: Análisis de comportamiento de procesos
   - `MLDetector`: Clasificación mediante modelos ONNX
   - `NetworkDetector`: Análisis de tráfico de red

3. **Monitores del Sistema**
   - `ProcessMonitor`: Monitoreo de procesos Windows
   - `FileMonitor`: Vigilancia de sistema de archivos
   - `NetworkMonitor`: Seguimiento de conexiones de red

4. **Sistema de Logging Avanzado**
   - 10 archivos de log independientes
   - Logging estructurado por componente
   - Monitoreo en tiempo real

5. **Interfaz Gráfica**
   - Dear PyGui (GPU-accelerated)
   - Tkinter (legacy)
   - Dashboard de métricas en tiempo real

### Evidencia del Código

```python
# core/engine.py
class UnifiedAntivirusEngine:
    """Motor principal del Sistema Anti-Keylogger Unificado."""
    # NO contiene capacidades de remediación
    # NO implementa desinfección de malware
    # SOLO detección y logging
```

```python
# plugins/detectors/keylogger_detector/keylogger_detector.py
class KeyloggerDetector(BasePlugin):
    """
    Plugin especializado en detección de keyloggers
    
    Basado en análisis de keyloggers reales:
    - Harem.c (hooks básicos)
    - Ghost_Writer.cs (keylogger avanzado C#)
    - EncryptedKeylogger.py (keylogger con cifrado)
    """
    
    # Patrones específicos de APIs de Windows
    suspicious_apis = [
        "SetWindowsHookEx",  # Principal API para hooks
        "GetAsyncKeyState",   # Estado de teclas async
        "BitBlt",            # Captura de pantalla
        # ... 100+ APIs catalogadas
    ]
```

---

## 2. OBJETIVOS REALES DEL SISTEMA

### Objetivos Identificados por Ingeniería Inversa

#### 2.1 Objetivo Principal: Investigación Académica
El sistema NO tiene como objetivo funcionar como un antivirus comercial o de producción. Su propósito es:

> **Investigar y catalogar patrones comportamentales de keyloggers mediante análisis de malware real**

**Evidencia**:
- Documentación interna menciona keyloggers específicos analizados (Harem.c, Ghost_Writer.cs)
- Patrones de archivos basados en observación de malware real
- Enfoque en detección, NO en remediación

#### 2.2 Objetivos Académicos Secundarios

1. **Implementación de Patrones de Diseño de Software**
   - Facade Pattern (UnifiedAntivirusEngine)
   - Observer Pattern (EventBus)
   - Factory Pattern (PluginManager)
   - Template Method (BasePlugin)
   - Strategy Pattern (Detectores)

   ```python
   # core/engine.py - Comentario del código
   """
   Implementa Facade Pattern que simplifica:
   - Gestión de plugins
   - Comunicación entre componentes
   - Ciclo de vida del sistema
   """
   ```

2. **Integración de Metodologías Modernas de Desarrollo**
   - **TDD** (Test-Driven Development): Tests automáticos cada 60s
   - **IAST** (Interactive Application Security Testing): Análisis de vulnerabilidades
   - **MDSD** (Model-Driven Software Development): Generación de código automático

3. **Análisis Comportamental de Malware**
   - Catalogar 100+ APIs de Windows usadas por keyloggers
   - Identificar patrones de archivos de log
   - Detectar técnicas de ocultación (stealth)
   - Analizar inyección de procesos

4. **Construcción de Framework Extensible**
   - Sistema de plugins dinámico
   - Event Bus para comunicación desacoplada
   - Arquitectura modular para investigación futura

---

## 3. MOTIVOS DEL DISEÑO

### ¿Por qué se construyó de esta manera?

#### 3.1 Contexto Académico

**Proyecto de Curso**: Sistemas Comportamentales - Universidad Privada de Tacna

El sistema fue diseñado para:
- Demostrar conocimientos de arquitectura de software
- Aplicar patrones de diseño en contexto real
- Investigar técnicas de detección de malware
- Cumplir con requisitos académicos de proyecto final

#### 3.2 Enfoque en Detección vs Remediación

El código revela una **decisión consciente** de enfocarse solo en detección:

```python
# keylogger_detector.py
def analyze_process_for_keylogger(self, process_data):
    """Analiza un proceso específico en busca de características de keylogger"""
    
    # Calcula scores de riesgo
    # Publica eventos de detección
    # NO termina procesos
    # NO elimina archivos
    # NO modifica sistema
```

**Motivos**:
1. **Seguridad**: Evitar daños al sistema operativo
2. **Legalidad**: No requiere permisos administrativos
3. **Investigación**: Observar sin interferir
4. **Académico**: Enfoque en análisis, no en acción

#### 3.3 Arquitectura de Plugins

La arquitectura modular permite:
- Agregar nuevos detectores sin modificar el core
- Investigadores pueden crear plugins personalizados
- Experimentación con diferentes técnicas de detección
- Demostración de principios SOLID

#### 3.4 Logging Extensivo

10 archivos de log independientes:
- `antivirus.log` - Sistema principal
- `keylogger_detector.log` - Detector de keyloggers
- `behavior_detector.log` - Análisis de comportamiento
- `tdd_integration.log` - Test-Driven Development
- `iast_security.log` - Security testing
- etc.

**Motivo**: Trazabilidad completa para análisis académico y debugging

---

## 4. CONCLUSIONES DEL ANÁLISIS

### 4.1 Discrepancia Documentación vs Código

| Aspecto | Documentación (README.md) | Código Real |
|---------|---------------------------|-------------|
| **Nombre** | "Sistema Antivirus Unificado" | Framework de Análisis Comportamental |
| **Propósito** | "Proteger sistemas contra amenazas" | Detectar y catalogar patrones de keyloggers |
| **Capacidades** | "Cuarentena, desinfección, protección" | Solo detección y logging |
| **Tipo** | "Antivirus de producción" | Proyecto de investigación académica |
| **Target** | "Usuarios finales" | Investigadores / Estudiantes |

### 4.2 Hallazgos Clave

#### ✅ Fortalezas Identificadas

1. **Arquitectura Sólida**
   - Patrones de diseño bien implementados
   - Código modular y extensible
   - Separación clara de responsabilidades

2. **Investigación Profunda**
   - Análisis detallado de keyloggers reales
   - Catalogación exhaustiva de APIs de Windows (100+)
   - Patrones de comportamiento bien documentados

3. **Desarrollo Profesional**
   - Testing automatizado (TDD)
   - Security testing (IAST)
   - Code generation (MDSD)
   - Logging estructurado

4. **Interfaz Completa**
   - Dear PyGui moderna
   - Dashboard responsive
   - Visualización de métricas en tiempo real

#### ⚠️ Limitaciones Identificadas

1. **NO es un Antivirus Funcional**
   - No elimina malware
   - No desinfecta archivos
   - No protege el sistema en tiempo real
   - Sistema de "cuarentena" no funcional

2. **Detección Limitada**
   - Solo patrones conocidos de keyloggers
   - Basado en heurísticas, no en firmas actualizadas
   - Sin conexión a bases de datos de amenazas
   - Posibles falsos positivos en procesos legítimos

3. **Sin Capacidades de Producción**
   - No está diseñado para uso comercial
   - Falta optimización de rendimiento
   - Sin soporte para actualizaciones automáticas
   - No cumple estándares de antivirus profesionales

### 4.3 Valor Académico

El proyecto es **excepcional como trabajo académico** porque:

1. ✅ Demuestra comprensión profunda de:
   - Arquitectura de software
   - Patrones de diseño
   - Análisis de malware
   - Metodologías de desarrollo (TDD, IAST, MDSD)

2. ✅ Implementa sistema complejo con:
   - Motor de plugins dinámico
   - Event-driven architecture
   - Machine Learning (modelos ONNX)
   - Interfaz gráfica avanzada

3. ✅ Investigación original sobre:
   - Patrones de keyloggers reales
   - Técnicas de detección comportamental
   - APIs de Windows usadas por malware

### 4.4 Conclusión Final

> **El sistema GENSEC NO es un antivirus funcional, sino un framework de investigación académica altamente sofisticado para el análisis de patrones comportamentales de keyloggers.**

**Su valor radica en**:
- 🎓 Calidad académica excepcional
- 🔬 Investigación original de malware
- 💻 Arquitectura de software profesional
- 📊 Sistema completo de análisis y logging

**NO debe ser usado para**:
- ❌ Protección real de sistemas en producción
- ❌ Sustituto de antivirus comerciales
- ❌ Eliminación de malware real
- ❌ Protección de datos críticos

---

## 5. RECOMENDACIONES

### 5.1 Para la Documentación

Se recomienda **corregir toda la documentación** para reflejar la realidad:

1. Cambiar "Sistema Antivirus" por **"Framework de Análisis Comportamental de Keyloggers"**
2. Eliminar referencias a "cuarentena" y "desinfección"
3. Agregar disclaimer: **"Sistema de investigación académica - NO usar en producción"**
4. Documentar correctamente:
   - Propósito académico
   - Limitaciones del sistema
   - Casos de uso apropiados

### 5.2 Para el Código

Si se desea hacer un antivirus real:

1. Implementar capacidades de remediación
2. Agregar sistema de cuarentena funcional
3. Integrar bases de datos de amenazas actualizadas
4. Optimizar rendimiento para producción
5. Implementar actualizaciones automáticas

### 5.3 Para el Proyecto Académico

El proyecto es **excelente para presentación académica** si se documenta correctamente:

1. Crear sección "Análisis de Malware Realizado"
2. Documentar keyloggers específicos analizados
3. Explicar decisiones de diseño
4. Mostrar patrones descubiertos
5. Presentar como **investigación**, no como producto

---

## 6. APÉNDICES

### 6.1 Keyloggers Analizados

El código menciona explícitamente:

1. **Harem.c**
   - Keylogger básico en C
   - Usa `SetWindowsHookEx` para hooks de teclado
   - Guarda logs en `readme.txt`
   - Técnica de ocultación: `ShowWindow(SW_HIDE)`

2. **Ghost_Writer.cs**
   - Keylogger avanzado en C#
   - Captura de pantalla con `BitBlt`
   - Guarda en carpetas `Text_Data` e `Image_Data`
   - Screenshots periódicos

3. **EncryptedKeylogger.py**
   - Keylogger con cifrado en Python
   - Encriptación de logs
   - Exfiltración por red

### 6.2 APIs de Windows Catalogadas

El sistema cataloga 100+ APIs, incluyendo:

**Hooks**:
- `SetWindowsHookEx` / `SetWindowsHookExW` / `SetWindowsHookExA`
- `CallNextHookEx` / `UnhookWindowsHookEx`
- `GetAsyncKeyState` / `GetKeyState`

**Captura de Pantalla**:
- `BitBlt` / `StretchBlt`
- `CreateCompatibleDC` / `CreateCompatibleBitmap`
- `SelectObject` / `GetDC`

**Inyección**:
- `WriteProcessMemory` / `VirtualAllocEx`
- `CreateRemoteThread` / `SetThreadContext`

**Stealth**:
- `ShowWindow` / `SetWindowPos`
- `IsDebuggerPresent` / `CheckRemoteDebuggerPresent`

### 6.3 Arquitectura de Plugins

```
plugins/
├── detectors/           # Detectores de amenazas
│   ├── keylogger_detector/
│   ├── behavior_detector/
│   ├── ml_detector/
│   ├── network_detector/
│   ├── iast_detector/
│   └── integration_engine/
│
├── monitors/            # Monitores del sistema
│   ├── process_monitor/
│   ├── file_monitor/
│   └── network_monitor/
│
└── handlers/            # Manejadores de eventos
    ├── alert_manager/
    ├── logger_handler/
    └── quarantine_handler/  # ⚠️ NO funcional
```

---

## 📝 Notas Finales

**Fecha del Análisis**: 2025-11-20  
**Método**: Ingeniería inversa del código fuente  
**Archivos Analizados**:
- `core/engine.py` (609 líneas)
- `plugins/detectors/keylogger_detector/keylogger_detector.py` (1687 líneas)
- `README.md` y múltiples archivos de documentación
- Estructura completa del proyecto

**Confidencialidad**: Análisis para uso académico

---

**Este análisis revela que GENSEC es un proyecto académico de alta calidad que demuestra competencias avanzadas en ingeniería de software, pero que requiere corrección urgente de su documentación para reflejar su verdadero propósito y evitar confusión sobre sus capacidades reales.**
