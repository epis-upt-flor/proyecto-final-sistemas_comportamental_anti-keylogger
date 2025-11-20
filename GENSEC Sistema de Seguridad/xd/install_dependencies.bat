@echo off
REM Instalador de dependencias - Sistema Anti-Keylogger
REM Ejecutar como administrador para mejores resultados

echo Instalando dependencias del Sistema Anti-Keylogger...
echo.

REM Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python no encontrado
    echo Instalar Python desde: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Actualizar pip
echo Actualizando pip...
python -m pip install --upgrade pip

REM Instalar dependencias
echo Instalando dependencias...
pip install psutil>=5.9.0
pip install watchdog>=2.1.9
pip install toml>=0.10.2
pip install onnxruntime>=1.15.0
pip install numpy>=1.24.0
pip install pandas>=2.0.0
pip install scikit-learn>=1.3.0
pip install python-dateutil>=2.8.2
pip install requests>=2.31.0

REM Verificar instalación
echo.
echo Verificando instalación...
python -c "import psutil, watchdog, onnxruntime, numpy, pandas, sklearn, toml, requests; print('Dependencias instaladas correctamente')"

if errorlevel 1 (
    echo Error en la instalación
    pause
    exit /b 1
)

echo.
echo Instalación completada
echo Para ejecutar: cd UI_ANTIVIRUS ^& python continuous_ui.py
pause