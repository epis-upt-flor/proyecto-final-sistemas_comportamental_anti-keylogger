@echo off
REM Instalador de dependencias - UNIFIED ANTIVIRUS + MDSD
REM Ejecutar como administrador para mejores resultados

echo ================================================
echo  UNIFIED ANTIVIRUS - Instalador de Dependencias
echo  Incluye soporte para MDSD (Model-Driven Software Development)
echo ================================================
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

REM Instalar dependencias core del antivirus
echo Instalando dependencias core...
pip install psutil>=5.9.0
pip install watchdog>=2.1.9
pip install toml>=0.10.2
pip install onnxruntime>=1.15.0
pip install numpy>=1.24.0
pip install pandas>=2.0.0
pip install scikit-learn>=1.3.0
pip install python-dateutil>=2.8.2
pip install requests>=2.31.0

REM Instalar dependencias MDSD (Model-Driven Software Development)
echo Instalando dependencias MDSD...
pip install PyYAML>=6.0
pip install schedule>=1.2.0

REM Instalar dependencias TDD y Testing
echo Instalando framework TDD...
pip install pytest>=7.4.0
pip install pytest-cov>=4.1.0
pip install pytest-mock>=3.11.0
pip install pytest-xdist>=3.3.0
pip install pytest-html>=3.2.0
pip install coverage>=7.3.0

echo Instalando herramientas de calidad...
pip install black>=23.0.0
pip install flake8>=6.0.0
pip install mypy>=1.5.0
pip install bandit>=1.7.5

REM Verificar instalación
echo.
echo Verificando instalación core...
python -c "import psutil, watchdog, onnxruntime, numpy, pandas, sklearn, toml, requests; print('✅ Dependencias core instaladas correctamente')"

echo Verificando instalación MDSD...
python -c "import yaml, schedule; print('✅ Dependencias MDSD instaladas correctamente')"

echo Verificando instalación TDD...
python -c "import pytest, coverage; print('✅ Framework TDD instalado correctamente')"

echo Verificando herramientas de calidad...
python -c "import black, flake8; print('✅ Herramientas de calidad instaladas')" 2>nul || echo "⚠️ Algunas herramientas opcionales no disponibles"

if errorlevel 1 (
    echo Error en la instalación
    pause
    exit /b 1
)

echo.
echo ================================================
echo 🎉 INSTALACIÓN COMPLETADA
echo ================================================
echo.
echo Funcionalidades disponibles:
echo   📡 Sistema Antivirus Core: Detectores ML, Behavior, Network
echo   🚀 MDSD Framework: Generación automática de detectores
echo   🔄 Workflows automáticos: Desarrollo y despliegue continuo
echo   🧪 TDD Framework: Test-Driven Development completo
echo.
echo Para ejecutar:
echo   🖥️  GUI Antivirus: python professional_ui_robust.py
echo   ⚙️  MDSD Generator: python mdsd/simple_generator.py
echo   🔄 Workflow Engine: python mdsd/workflow_engine.py
echo   🧪 Tests TDD: pytest tests/
echo   📊 Cobertura: pytest --cov=. tests/
echo   🔍 Calidad: black . ^& flake8 . ^& mypy .
echo.
pause