# 🔬 GENSEC - Framework de Análisis Comportamental

## 📌 ¿Qué es GENSEC?

**GENSEC** es un **Framework de Análisis Comportamental de Procesos** que monitorea lo que hacen los programas en tu computadora y detecta si se comportan de manera sospechosa, especialmente si parecen ser keyloggers (programas que espían lo que escribes).

### En Palabras Simples

Imagina que GENSEC es como un detective que:
1. 👀 **Observa** todo lo que hacen los programas en tu computadora
2. 📋 **Registra** sus acciones en archivos de log
3. 🔍 **Analiza** si esas acciones son sospechosas
4. 🚨 **Alerta** cuando encuentra algo que parece malicioso
5. 📊 **Reporta** sus hallazgos para que los investigues

**IMPORTANTE:** GENSEC **NO elimina ni bloquea** programas maliciosos. Solo los **detecta y reporta**.

---

## 🎯 ¿Para Qué Sirve?

### ✅ Lo Que SÍ Hace:

- **Monitorea procesos** que se ejecutan en Windows
- **Detecta patrones** de comportamiento sospechoso
- **Analiza APIs de Windows** que usan los programas
- **Identifica keyloggers** basándose en cómo se comportan
- **Genera logs detallados** de todo lo que encuentra
- **Calcula scores de riesgo** para cada proceso

### ❌ Lo Que NO Hace:

- NO elimina malware
- NO bloquea procesos sospechosos
- NO desinfecta archivos
- NO reemplaza a un antivirus comercial

---

## 🔄 Flujo de Funcionamiento - Paso a Paso

### Fase 1: Inicio del Sistema 🚀

```
Usuario ejecuta: python production_launcher.py
            ↓
    [Motor Principal se inicia]
            ↓
    [Descubre y carga plugins]
            ↓
    [Activa 8 plugins en orden]
            ↓
    [Sistema listo para analizar]
```

**¿Qué está pasando?**
- El motor principal (`UnifiedAntivirusEngine`) arranca
- Busca automáticamente todos los plugins disponibles
- Los carga en memoria
- Los activa en el orden correcto
- El sistema entra en modo de monitoreo continuo

---

### Fase 2: Monitoreo Continuo 👁️

Una vez iniciado, el sistema tiene **3 tipos de monitores** trabajando simultáneamente:

#### 1. **Monitor de Procesos** 📊

```
Cada 5 segundos:
    ├─ Escanea todos los procesos activos de Windows
    ├─ Captura información de cada proceso:
    │   ├─ PID (identificador único)
    │   ├─ Nombre del programa
    │   ├─ Uso de CPU y memoria
    │   ├─ Ubicación del archivo ejecutable
    │   └─ Línea de comandos usada
    └─ Envía esta información al Event Bus
```

**Ejemplo real:**
```
Detectado: notepad.exe
├─ PID: 1234
├─ Memoria: 15 MB
├─ CPU: 0.2%
└─ Path: C:\Windows\System32\notepad.exe
```

#### 2. **Monitor de Archivos** 📁

```
En tiempo real:
    ├─ Vigila carpetas críticas del sistema
    ├─ Detecta cuando se crean, modifican o eliminan archivos
    ├─ Identifica patrones sospechosos:
    │   ├─ Archivos .log con timestamps
    │   ├─ Archivos ocultos en carpetas de usuario
    │   └─ Modificaciones masivas (ransomware)
    └─ Envía alertas al Event Bus
```

**Ejemplo real:**
```
Detectado: C:\Users\Usuario\readme.txt
├─ Acción: ARCHIVO CREADO
├─ Tamaño: 2 KB
├─ Contenido sospechoso: contiene timestamps de teclas
└─ Score de sospecha: 75%
```

#### 3. **Monitor de Red** 🌐

```
Cada 10 segundos:
    ├─ Lista todas las conexiones de red activas
    ├─ Por cada conexión captura:
    │   ├─ Proceso que la creó
    │   ├─ IP y puerto de destino
    │   ├─ Cantidad de datos enviados/recibidos
    │   └─ Estado de la conexión
    └─ Busca conexiones a IPs maliciosas conocidas
```

**Ejemplo real:**
```
Detectado: svchost.exe
├─ Conexión a: 192.168.1.100:443
├─ Datos enviados: 500 KB
├─ Verificación: IP en lista de IPs maliciosas → NO
└─ Score de riesgo: BAJO
```

---

### Fase 3: Análisis de Comportamiento 🔍

Cuando los monitores detectan algo, los **detectores** entran en acción:

#### Detector 1: **Keylogger Detector** 🎹

```
Recibe información de un proceso
        ↓
Verifica si está usando APIs sospechosas:
├─ SetWindowsHookEx (para capturar teclas)
├─ GetAsyncKeyState (para leer estado de teclas)
├─ GetForegroundWindow (para saber qué ventana está activa)
├─ BitBlt (para capturar pantalla)
└─ WriteFile hacia archivos .log
        ↓
Calcula SCORE DE SOSPECHA (0-100%)
        ↓
Si score > 70% → ALERTA DE KEYLOGGER
```

**Ejemplo de análisis:**
```
Proceso: MiPrograma.exe
├─ Usa SetWindowsHookEx: SÍ (+40 puntos)
├─ Usa GetAsyncKeyState: SÍ (+30 puntos)
├─ Escribe a archivo .log: SÍ (+20 puntos)
├─ Archivo oculto: SÍ (+10 puntos)
│
└─ SCORE TOTAL: 100% → ⚠️ KEYLOGGER DETECTADO
```

#### Detector 2: **Behavior Detector** 👁️

```
Analiza el comportamiento general del proceso:
├─ ¿Inyecta código en otros procesos?
├─ ¿Modifica archivos del sistema?
├─ ¿Se inicia automáticamente con Windows?
├─ ¿Intenta ocultarse (stealth)?
└─ ¿Usa técnicas de anti-debugging?
        ↓
Calcula NIVEL DE RIESGO: NORMAL/LOW/MEDIUM/HIGH
```

**Ejemplo:**
```
Proceso: UpdateService.exe
├─ Inyección de código: NO
├─ Modificación de sistema: NO
├─ Auto-inicio: SÍ (normal para servicios)
├─ Stealth: NO
│
└─ Nivel de Riesgo: NORMAL
```

#### Detector 3: **ML Detector** 🤖

```
Extrae 15+ características del proceso:
├─ Uso de memoria
├─ Uso de CPU
├─ Cantidad de threads
├─ APIs llamadas
├─ Conexiones de red
├─ Archivos abiertos
└─ ... (más características)
        ↓
Alimenta el modelo de Machine Learning (ONNX)
        ↓
Modelo predice: ¿Es keylogger? (0.0 - 1.0)
        ↓
Si predicción > 0.5 → POSIBLE KEYLOGGER
```

**Ejemplo:**
```
Proceso: Desconocido.exe
├─ Features extraídas: [15.2 MB, 2.5% CPU, 8 threads, ...]
├─ Modelo ML predice: 0.87 (87% probabilidad de ser keylogger)
│
└─ Clasificación: ⚠️ AMENAZA DETECTADA
```

#### Detector 4: **Network Detector** 🌐

```
Analiza tráfico de red del proceso:
├─ ¿Envía datos a servidores desconocidos?
├─ ¿La IP destino está en lista de IPs maliciosas?
├─ ¿Cantidad de datos sospechosa?
├─ ¿Puerto usado es común para C&C servers?
└─ ¿Consultas DNS sospechosas?
        ↓
Calcula RIESGO DE RED
```

---

### Fase 4: Sistema de Consenso 🤝

Cuando múltiples detectores analizan el mismo proceso, sus resultados se **combinan**:

```
Proceso bajo análisis: sospechoso.exe

Resultados individuales:
├─ Keylogger Detector: 85% sospecha → HIGH
├─ Behavior Detector: 60% sospecha → MEDIUM
├─ ML Detector: 75% probabilidad → HIGH
└─ Network Detector: 40% riesgo → LOW

        ↓
   [Motor de Consenso]
        ↓
Aplica ponderación:
├─ Keylogger Detector: 85% × 0.3 = 25.5
├─ Behavior Detector: 60% × 0.2 = 12.0
├─ ML Detector: 75% × 0.4 = 30.0
└─ Network Detector: 40% × 0.1 = 4.0
        ↓
SCORE FINAL = 71.5% → 🚨 AMENAZA CONFIRMADA
```

**¿Por qué consenso?**
- Un solo detector puede equivocarse (falso positivo)
- Múltiples detectores de acuerdo = mayor confianza
- Cada detector tiene un "peso" según su precisión

---

### Fase 5: Event Bus - Comunicación 📡

El **Event Bus** es como un sistema de mensajería interno:

```
Detector encuentra algo sospechoso
        ↓
Publica evento: "threat_detected"
        ↓
Event Bus distribuye a todos los suscriptores:
├─ Logger Handler (guarda en logs)
├─ Alert Manager (genera alerta)
├─ UI (actualiza interfaz gráfica)
└─ Quarantine Handler (marca para cuarentena)
```

**Flujo de un evento:**
```
[Keylogger Detector]
    publica evento THREAT_DETECTED
        ↓
    [Event Bus]
        ├─ notifica → [Logger Handler]
        │              └─ escribe en keylogger_detector.log
        │
        ├─ notifica → [Alert Manager]
        │              └─ genera alerta visual en UI
        │
        └─ notifica → [Frontend]
                       └─ muestra amenaza en dashboard
```

---

### Fase 6: Logging y Reportes 📊

Todo lo que sucede se **registra en 10 archivos de log diferentes**:

```
logs/
├─ antivirus.log              ← Log principal del sistema
├─ keylogger_detector.log     ← Detecciones de keyloggers
├─ behavior_detector.log      ← Análisis de comportamiento
├─ ml_detector.log            ← Predicciones de ML
├─ network_detector.log       ← Análisis de red
├─ process_monitor.log        ← Procesos monitoreados
├─ file_monitor.log           ← Cambios en archivos
├─ tdd_integration.log        ← Tests automáticos
├─ iast_security.log          ← Tests de seguridad
└─ mdsd_generator.log         ← Generación de código
```

**Ejemplo de entrada en log:**
```
2025-11-21 15:45:23 - keylogger_detector - WARNING - 
🚨 KEYLOGGER DETECTADO
├─ Proceso: KeyCapture.exe
├─ PID: 5678
├─ Score: 92%
├─ Razones:
│   ├─ Usa SetWindowsHookEx
│   ├─ Escribe a archivo .log
│   └─ Proceso oculto
└─ Recomendación: Investigar inmediatamente
```

---

## 📊 Interfaz Gráfica - Dashboard

El usuario ve todo esto en tiempo real a través del **Dashboard Dear PyGui**:

```
┌─────────────────────────────────────────────────────────┐
│  🛡️ GENSEC - Framework de Análisis Comportamental      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  📊 MÉTRICAS EN TIEMPO REAL                             │
│  ┌─────────────┬─────────────┬─────────────┐           │
│  │ Amenazas: 3 │ Procesos: 67│ Uptime: 2h  │           │
│  └─────────────┴─────────────┴─────────────┘           │
│                                                          │
│  🚨 AMENAZAS DETECTADAS                                 │
│  ┌───────────────────────────────────────────┐         │
│  │ ⚠️ KeyCapture.exe (PID 5678) - 92%        │         │
│  │ ⚠️ ScreenLogger.exe (PID 9012) - 85%      │         │
│  │ ⚠️ HiddenSpy.exe (PID 3456) - 78%         │         │
│  └───────────────────────────────────────────┘         │
│                                                          │
│  📈 GRÁFICO DE ACTIVIDAD                                │
│  [Gráfico de líneas mostrando detecciones en el tiempo]│
│                                                          │
│  📋 LOGS EN VIVO                                        │
│  2025-11-21 15:45:23 - Keylogger detectado              │
│  2025-11-21 15:45:20 - Proceso sospechoso analizado     │
│  2025-11-21 15:45:15 - Conexión de red verificada       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🔄 Flujo Completo de Análisis (Diagram a)

```
INICIO
  ↓
┌─────────────────────────────────────────────┐
│ 1. Usuario ejecuta el sistema              │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 2. Motor principal carga 8 plugins          │
│    ├─ 4 Detectores                          │
│    ├─ 3 Monitores                           │
│    └─ 3 Handlers                            │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 3. Monitores comienzan a vigilar:          │
│    ├─ Procesos (cada 5s)                    │
│    ├─ Archivos (tiempo real)                │
│    └─ Red (cada 10s)                        │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 4. Se detecta un nuevo proceso              │
│    Ejemplo: "MiPrograma.exe"                │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 5. Monitor publica evento al Event Bus      │
│    Evento: "process_detected"               │
│    Data: {pid: 1234, name: "MiPrograma...} │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 6. Los 4 detectores analizan el proceso:    │
│    ┌───────────────────────────────┐        │
│    │ Keylogger Detector            │        │
│    │ └─ Verifica APIs sospechosas  │        │
│    │    Resultado: 85% sospecha    │        │
│    └───────────────────────────────┘        │
│    ┌───────────────────────────────┐        │
│    │ Behavior Detector             │        │
│    │ └─ Analiza comportamiento     │        │
│    │    Resultado: 70% sospecha    │        │
│    └───────────────────────────────┘        │
│    ┌───────────────────────────────┐        │
│    │ ML Detector                   │        │
│    │ └─ Ejecuta modelo ONNX        │        │
│    │    Resultado: 0.75 probabilid.│        │
│    └───────────────────────────────┘        │
│    ┌───────────────────────────────┐        │
│    │ Network Detector              │        │
│    │ └─ Revisa conexiones          │        │
│    │    Resultado: 40% riesgo      │        │
│    └───────────────────────────────┘        │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 7. Motor de Consenso combina resultados     │
│    Score ponderado: 71.5%                   │
│    Clasificación: AMENAZA (HIGH)            │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 8. Se publica evento "threat_detected"      │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 9. Handlers procesan la amenaza:            │
│    ├─ Logger → Escribe en logs              │
│    ├─ Alert Manager → Genera alerta UI      │
│    └─ Quarantine → Marca para cuarentena    │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 10. Usuario ve la amenaza en Dashboard      │
│     "⚠️ MiPrograma.exe - KEYLOGGER (71.5%)" │
└─────────────────────────────────────────────┘
  ↓
┌─────────────────────────────────────────────┐
│ 11. Sistema continúa monitoreando...        │
│     (Vuelve al paso 3)                      │
└─────────────────────────────────────────────┘
```

---

## 🧩 Componentes del Sistema

### Core (Núcleo)

| Componente | Función |
|------------|---------|
| **Engine** | Motor principal que coordina todo |
| **Plugin Manager** | Carga y gestiona los plugins |
| **Event Bus** | Sistema de mensajería interna |
| **Plugin Registry** | Registro de plugins disponibles |

### Plugins - Detectores

| Detector | Qué Detecta |
|----------|-------------|
| **Keylogger Detector** | Programas que capturan teclas |
| **Behavior Detector** | Comportamiento sospechoso general |
| **ML Detector** | Amenazas usando Machine Learning |
| **Network Detector** | Conexiones maliciosas |

### Plugins - Monitores

| Monitor | Qué Vigila |
|---------|------------|
| **Process Monitor** | Procesos en ejecución |
| **File Monitor** | Cambios en archivos |
| **Network Monitor** | Conexiones de red |

### Plugins - Handlers

| Handler | Qué Hace |
|---------|----------|
| **Logger Handler** | Guarda todo en logs |
| **Alert Manager** | Genera alertas visuales |
| **Quarantine Handler** | Marca archivos para cuarentena |

---

## 💡 Ejemplo Práctico Completo

Imagina que un usuario descarga accidentalmente un keylogger llamado `KeySpy.exe`:

### 1️⃣ **Usuario ejecuta KeySpy.exe**

```
Windows inicia el proceso:
├─ PID: 7890
├─ Path: C:\Users\Usuario\Downloads\KeySpy.exe
└─ Estado: Running
```

### 2️⃣ **Process Monitor lo detecta**

```
[5 segundos después]
Process Monitor escanea procesos activos
├─ Encuentra: KeySpy.exe (PID 7890)
├─ Captura información:
│   ├─ Memoria: 8 MB
│   ├─ CPU: 1.5%
│   └─ Path: C:\Users\Usuario\Downloads\
└─ Publica evento: "new_process_detected"
```

### 3️⃣ **Keylogger Detector analiza**

```
Keylogger Detector recibe el evento
├─ Analiza APIs usadas por KeySpy.exe:
│   ├─ SetWindowsHookEx → ✅ DETECTADA
│   ├─ GetAsyncKeyState → ✅ DETECTADA
│   ├─ GetForegroundWindow → ✅ DETECTADA
│   └─ WriteFile (a "keylog.txt") → ✅ DETECTADA
│
├─ Calcula score:
│   ├─ Hooking APIs: +50 puntos
│   ├─ Captura de teclas: +30 puntos
│   └─ Escribe logs: +20 puntos
│
└─ TOTAL: 100% → 🚨 KEYLOGGER CONFIRMADO
```

### 4️⃣ **ML Detector confirma**

```
ML Detector extrae features:
├─ Memoria baja (8 MB): típico de keyloggers
├─ Pocas threads: sospechoso
├─ APIs de hooking: muy sospechoso
└─ Modelo predice: 0.94 (94% keylogger)
```

### 5️⃣ **File Monitor encuentra el archivo de log**

```
File Monitor detecta:
├─ Nuevo archivo: C:\Users\Usuario\keylog.txt
├─ Contenido:
│   [2025-11-21 15:30:12] : h
│   [2025-11-21 15:30:13] : e
│   [2025-11-21 15:30:14] : l
│   [2025-11-21 15:30:15] : l
│   [2025-11-21 15:30:16] : o
│
└─ Patrón de keylogger confirmado: 100%
```

### 6️⃣ **Consenso final**

```
Motor de Consenso combina:
├─ Keylogger Detector: 100%
├─ ML Detector: 94%
├─ Behavior Detector: 85%
├─ File Monitor: 100%
│
└─ RESULTADO FINAL: 95% → AMENAZA CRÍTICA
```

### 7️⃣ **Sistema alerta al usuario**

```
Dashboard muestra:
┌────────────────────────────────────────┐
│ 🚨 AMENAZA CRÍTICA DETECTADA           │
├────────────────────────────────────────┤
│ Proceso: KeySpy.exe                    │
│ Riesgo: 95% (CRÍTICO)                  │
│ Tipo: KEYLOGGER                        │
│                                         │
│ Evidencia:                              │
│ ✅ Usa hooks de teclado                │
│ ✅ Captura teclas presionadas          │
│ ✅ Guarda en archivo keylog.txt        │
│ ✅ ML confirma como keylogger          │
│                                         │
│ Recomendación:                          │
│ Finalizar proceso inmediatamente y     │
│ eliminar archivo con antivirus real    │
└────────────────────────────────────────┘
```

---

## 🎯 Resumen del Flujo en 3 Pasos

1. **MONITOREO** 👁️
   - Vigilancia continua de procesos, archivos y red

2. **ANÁLISIS** 🔍
   - 4 detectores analizan cada proceso desde diferentes ángulos

3. **REPORTE** 📊
   - Combina resultados, genera alertas y registra en logs

---

## 🚀 Cómo Ejecutar el Sistema

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Ejecutar con interfaz gráfica
python production_launcher.py

# 3. El sistema comienza a analizar automáticamente
```

---

## 📚 Archivos de Log que se Generan

Todos los logs están en la carpeta `logs/`:

- `antivirus.log` - Log principal
- `keylogger_detector.log` - Detecciones de keyloggers
- `behavior_detector.log` - Análisis de comportamiento
- `ml_detector.log` - Predicciones de ML
- `network_detector.log` - Análisis de red
- Y 5 más...

---

## ⚠️ Importante Recordar

1. ✅ GENSEC **DETECTA** amenazas
2. ❌ GENSEC **NO ELIMINA** amenazas
3. 📚 Es un **framework educativo** para investigación
4. 🛡️ **NO sustituye** a un antivirus comercial

---

## 📖 Documentos Relacionados

- `PROPOSITO_REAL_DEL_SISTEMA.md` - Análisis completo del sistema
- `INGENIERIA_INVERSA.md` - Análisis técnico del código
- `ANALISIS_SISTEMA_COMPLETO.md` - Documentación detallada

---

**Versión:** 1.0  
**Creado:** Noviembre 2025  
**Propósito:** Explicar el funcionamiento de GENSEC como Framework de Análisis Comportamental
