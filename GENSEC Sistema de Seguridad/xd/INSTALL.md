# 🛡️ Sistema Anti-Keylogger - Guía de Instalación

## 📋 Requisitos del Sistema

### Sistema Operativo
- **Windows 10/11** (x64)
- **Permisos de Administrador** (requerido para monitoreo de procesos)

### Python
- **Python 3.9+** (recomendado 3.11 o superior)
- **pip** (gestor de paquetes de Python)

## 📦 Dependencias Requeridas

### Paquetes Python Principales
```bash
# Machine Learning y Data Science
pip install numpy pandas scikit-learn

# Modelos ONNX para detección optimizada
pip install onnxruntime

# Monitoreo del sistema
pip install psutil

# Configuración y logging
pip install toml

# Interfaz de usuario (opcional)
pip install tkinter  # Generalmente incluido con Python
```

### Instalación Completa con un Comando
```bash
pip install numpy pandas scikit-learn onnxruntime psutil toml python-magic-bin
```

### Para Sistemas Windows (Recomendado)
```bash
# Versión específica para Windows que incluye libmagic
pip install numpy pandas scikit-learn onnxruntime psutil toml python-magic-bin==0.4.14
```

### Verificación de Instalación
```bash
python -c "import numpy, pandas, sklearn, onnxruntime, psutil, toml, magic; print('✅ Todas las dependencias instaladas correctamente')"
```

### Si el test falla, verificar una por una:
```bash
python -c "import numpy; print('✅ NumPy OK')"
python -c "import pandas; print('✅ Pandas OK')"  
python -c "import sklearn; print('✅ Scikit-learn OK')"
python -c "import onnxruntime; print('✅ ONNX Runtime OK')"
python -c "import psutil; print('✅ PSUtil OK')"
python -c "import toml; print('✅ TOML OK')"
python -c "import magic; print('✅ Python-magic OK')"
```

## 🚀 Comandos de Ejecución

### Navegación al Directorio del Sistema
```bash
cd "ANTIVIRUS_PRODUCTION"
```

### Opciones de Lanzamiento

#### 1. **Launcher Simple** (Recomendado para pruebas)
```bash
python simple_launcher.py
```

#### 2. **Launcher Completo** (Sistema completo con interfaz)
```bash
python antivirus_launcher.py
```

#### 3. **Demo Interactivo** (Para demostraciones)
```bash
python demo_launcher.py
```



## ⚙️ Configuración Inicial

### Verificar Configuración
```bash
# Revisar configuración del sistema
type config.toml
```

### Configurar Lista Blanca (Opcional)
El sistema ya incluye una lista blanca preconfigurada con aplicaciones comunes:
- Chrome, Firefox, Edge, Opera GX
- VS Code, GitHub Desktop
- Steam, Discord, Spotify
- Office (Word, Excel, PowerPoint)
- Herramientas del sistema de Windows

### Directorios de Confianza Preconfigurados
- `C:\Program Files\`
- `C:\Program Files (x86)\`
- `C:\Windows\System32\`
- `C:\Users\%USERNAME%\AppData\Local\Programs\`

## 🔧 Resolución de Problemas

### Error: "No module named 'onnxruntime'"
```bash
pip install onnxruntime
```

### Error: "No module named 'psutil'"
```bash
pip install psutil
```

### Error: Permisos Insuficientes
- Ejecutar terminal como **Administrador**
- Clic derecho en PowerShell/CMD → "Ejecutar como administrador"

### Error: Falsos Positivos
El sistema está configurado con:
- **Modo Seguro activado** (kill_processes = false)
- **Umbrales altos de detección** (0.95-0.98)
- **Sistema de verificación multicapa**
- **Lista blanca comprehensiva**

### Verificar Estado del Sistema
```bash
# Ver logs del antivirus
Get-Content -Tail 20 antivirus.log

# Ver eventos de seguridad
Get-Content -Tail 20 security_events.log
```

## 📊 Modelos de Machine Learning

### Ubicación de Modelos
```
models/
├── development/
│   ├── modelo_keylogger_from_datos.onnx  # Modelo ONNX optimizado
│   ├── metadata.json                     # Metadatos del modelo (81 features)
│   └── label_classes.json               # Clases: ['Benign', 'Keylogger']
└── keylogger_model_large_20250918_112840.onnx  # Modelo alternativo
```

### Características del Modelo
- **81 características** de flujos de red
- **Precisión optimizada** para detección de keyloggers
- **Formato ONNX** para inferencia rápida
- **Clases**: Benigno / Keylogger

## 🔄 Actualización del Sistema

### Actualizar Dependencias
```bash
pip install --upgrade numpy pandas scikit-learn onnxruntime psutil toml
```

### Limpiar Cache de Python
```bash
# PowerShell
Get-ChildItem -Recurse -Directory __pycache__ | Remove-Item -Recurse -Force
Get-ChildItem -Recurse *.pyc | Remove-Item -Force

# CMD
for /d /r . %d in (__pycache__) do @if exist "%d" rd /s /q "%d"
del /s /q *.pyc
```

## 🛡️ Características de Seguridad

### Sistema Inteligente Rehabilitado
- **Verificación multicapa** antes de tomar acciones
- **Lista blanca de procesos** y directorios confiables  
- **Análisis de comportamiento** avanzado
- **Detección ML** con modelo ONNX optimizado
- **Monitoreo de red** en tiempo real
- **Protección de procesos críticos** del sistema

### Configuración de Seguridad
- `threat_threshold = 0.98` (muy restrictivo)
- `safe_mode = true` (modo seguro activado)
- `kill_processes = false` (no termina procesos automáticamente)
- `enable_whitelist = true` (lista blanca activa)

## 📝 Logs y Monitoreo

### Archivos de Log
- `antivirus.log` - Log principal del sistema
- `security_events.log` - Eventos de seguridad detectados

### Monitoreo en Tiempo Real
```bash
# Ver logs en tiempo real
Get-Content -Wait antivirus.log
```

---

## ⚡ Inicio Rápido (TL;DR)

```bash
# 1. Instalar dependencias (Windows)
pip install numpy pandas scikit-learn onnxruntime psutil toml python-magic-bin

# 2. Navegar al directorio
cd "ANTIVIRUS_PRODUCTION"

# 3. Ejecutar sistema
python antivirus_launcher.py
```

## 🚨 Troubleshooting para Otras PCs

### Verificación de Requisitos
```bash
# Verificar versión de Python (debe ser 3.9+)
python --version

# Verificar dependencias instaladas
pip list | findstr "numpy pandas scikit-learn onnxruntime psutil toml python-magic"

# Verificar archivos del modelo
dir models\development\*.json
dir models\development\*.onnx
```

### Errores Comunes y Soluciones

#### Error: "No module named 'onnxruntime'"
```bash
pip install onnxruntime
# Si persiste el error:
pip install --upgrade pip
pip install onnxruntime --force-reinstall
```

#### Error: "python-magic" o "libmagic" no encontrado
```bash
# Instalar python-magic para Windows
pip install python-magic-bin

# O alternativamente:
pip install python-magic
pip install python-magic-bin --force-reinstall

# Si sigue fallando, usar la versión específica para Windows:
pip uninstall python-magic
pip install python-magic-bin==0.4.14
```

#### Error: "Permission denied" o "Access denied"
- **Ejecutar PowerShell como Administrador**
- Clic derecho en PowerShell → "Ejecutar como administrador"

#### Error: "File not found" para modelos
```bash
# Verificar estructura de archivos
cd ANTIVIRUS_PRODUCTION
dir models\development\
# Debe mostrar: metadata.json, modelo_keylogger_from_datos.onnx, label_classes.json
```

#### Sistema se cuelga al inicializar
```bash
# Limpiar cache de Python
Get-ChildItem -Recurse -Directory __pycache__ | Remove-Item -Recurse -Force
Get-ChildItem -Recurse *.pyc | Remove-Item -Force

# Ejecutar test básico primero
python test_ml_detector.py
```

#### Error: "charmap codec can't decode"
- Sistema detectado y ya corregido
- El sistema funciona con advertencias menores

### Test de Verificación Completa
```bash
# 1. Test del ML detector
cd ANTIVIRUS_PRODUCTION
python test_ml_detector.py

# 2. Test completo del sistema
python test_complete.py

# 3. Si ambos pasan, ejecutar sistema completo
python antivirus_launcher.py
```

---

**🔒 Sistema Anti-Keylogger v2.0 - Rehabilitado y Optimizado**
**✅ Verificado y funcionando en Windows 10/11**