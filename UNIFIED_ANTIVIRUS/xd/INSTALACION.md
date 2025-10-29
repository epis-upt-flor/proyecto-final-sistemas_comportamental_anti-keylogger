# 🚀 Instalación Rápida - Sistema Anti-Keylogger

## 📋 **Métodos de Instalación**

### 🎯 **Método 1: Instalación Automática (Recomendado)**

#### **Windows CMD/PowerShell:**
```cmd
# Ejecutar instalador automático
install_dependencies.bat
```

#### **PowerShell:**
```powershell
# Ejecutar instalador de PowerShell
.\Install-Dependencies.ps1
```

### 🎯 **Método 2: Instalación Manual**

#### **Dependencias Esenciales:**
```cmd
pip install psutil>=5.9.0 watchdog>=2.1.9 toml>=0.10.2 onnxruntime>=1.15.0 numpy>=1.24.0 pandas>=2.0.0 scikit-learn>=1.3.0
```

#### **Con archivo requirements:**
```cmd
# Solo dependencias esenciales
pip install -r requirements-minimal.txt

# Todas las dependencias (incluye análisis y desarrollo)
pip install -r requirements.txt
```

### 🎯 **Método 3: Con Entorno Virtual (Más Seguro)**

```cmd
# Crear entorno virtual
python -m venv antivirus_env

# Activar entorno
antivirus_env\Scripts\activate

# Instalar dependencias
pip install -r requirements-minimal.txt

# Ejecutar sistema
cd UI_ANTIVIRUS
python continuous_ui.py
```

## ✅ **Verificación de Instalación**

```python
# Verificar que todo funciona
python -c "import psutil, watchdog, onnxruntime, numpy, pandas, sklearn; print('✅ Todo instalado correctamente')"
```

## 🚀 **Ejecutar el Sistema**

```cmd
cd UI_ANTIVIRUS
python continuous_ui.py
```

## 📋 **Requisitos Previos**

- **Python 3.13+** ([Descargar](https://www.python.org/downloads/))
- **Windows 10/11** 
- **Permisos de Administrador** (recomendado)
- **4GB RAM** mínimo

## ❗ **Problemas Comunes**

| Problema | Solución |
|----------|----------|
| `python` no reconocido | Instalar Python y marcar "Add to PATH" |
| Error de permisos | Ejecutar como administrador |
| Falla onnxruntime | `pip install --upgrade onnxruntime` |
| Falta tkinter | Viene con Python estándar, reinstalar Python |

## 📞 **Soporte**

Si tienes problemas:
1. Ejecuta `install_dependencies.bat` como administrador
2. Verifica que Python esté en PATH
3. Usa entorno virtual para evitar conflictos