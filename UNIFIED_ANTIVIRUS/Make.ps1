# TDD Makefile para PowerShell
# =================================

param(
    [string]$Command = "help"
)

function Show-Help {
    Write-Host "TDD Development Commands" -ForegroundColor Green
    Write-Host "========================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Instalacion y Setup:"
    Write-Host "  .\Make.ps1 install      # Instalar todas las dependencias"
    Write-Host "  .\Make.ps1 check        # Verificar dependencias"
    Write-Host ""
    Write-Host "TDD Workflows:"
    Write-Host "  .\Make.ps1 red          # Fase RED - Ejecutar tests (fallar)"
    Write-Host "  .\Make.ps1 green        # Fase GREEN - Ejecutar tests (pasar)"
    Write-Host "  .\Make.ps1 refactor     # Fase REFACTOR - Calidad codigo"
    Write-Host "  .\Make.ps1 tdd-cycle    # Ciclo TDD completo"
    Write-Host ""
    Write-Host "Testing:"
    Write-Host "  .\Make.ps1 test         # Ejecutar todos los tests"
    Write-Host "  .\Make.ps1 test-unit    # Solo tests unitarios"
    Write-Host "  .\Make.ps1 test-tdd     # Solo tests TDD"
    Write-Host "  .\Make.ps1 coverage     # Reporte de cobertura"
    Write-Host ""
    Write-Host "Calidad de Codigo:"
    Write-Host "  .\Make.ps1 format       # Formatear codigo (Black)"
    Write-Host "  .\Make.ps1 lint         # Linting (Flake8)"
    Write-Host "  .\Make.ps1 type-check   # Type checking (MyPy)"
    Write-Host "  .\Make.ps1 security     # Analisis seguridad (Bandit)"
    Write-Host "  .\Make.ps1 quality      # Todas las verificaciones"
    Write-Host ""
    Write-Host "CI/CD:"
    Write-Host "  .\Make.ps1 ci           # Pipeline CI completo"
    Write-Host "  .\Make.ps1 pre-commit   # Verificaciones pre-commit"
    Write-Host ""
    Write-Host "Limpieza:"
    Write-Host "  .\Make.ps1 clean        # Limpiar archivos temporales"
    Write-Host "  .\Make.ps1 clean-all    # Limpieza completa"
}

function Install-Dependencies {
    Write-Host "Instalando dependencias..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Dependencias instaladas correctamente" -ForegroundColor Green
    } else {
        Write-Host "Error instalando dependencias" -ForegroundColor Red
        exit 1
    }
}

function Test-Dependencies {
    Write-Host "Verificando dependencias..." -ForegroundColor Yellow
    python tdd_runner.py --check
}

function Invoke-RedPhase {
    Write-Host "FASE RED - Tests deberian fallar" -ForegroundColor Red
    python tdd_runner.py --phase red
}

function Invoke-GreenPhase {
    Write-Host "FASE GREEN - Tests deberian pasar" -ForegroundColor Green
    python tdd_runner.py --phase green
}

function Invoke-RefactorPhase {
    Write-Host "FASE REFACTOR - Mejorando calidad" -ForegroundColor Blue
    python tdd_runner.py --phase refactor
}

function Invoke-TDDCycle {
    Write-Host "CICLO TDD COMPLETO" -ForegroundColor Magenta
    Write-Host "1. Fase RED..." -ForegroundColor Red
    Invoke-RedPhase
    
    Write-Host "`n2. Implementa tu codigo y presiona Enter para continuar..." -ForegroundColor Yellow
    Read-Host
    
    Write-Host "3. Fase GREEN..." -ForegroundColor Green
    Invoke-GreenPhase
    
    Write-Host "`n4. Fase REFACTOR..." -ForegroundColor Blue
    Invoke-RefactorPhase
    
    Write-Host "`nCiclo TDD completado" -ForegroundColor Green
}

function Invoke-AllTests {
    Write-Host "Ejecutando todos los tests..." -ForegroundColor Yellow
    pytest tests/ -v
}

function Invoke-UnitTests {
    Write-Host "Ejecutando tests unitarios..." -ForegroundColor Yellow
    pytest -m unit -v
}

function Invoke-TDDTests {
    Write-Host "Ejecutando tests TDD..." -ForegroundColor Yellow
    pytest -m tdd -v
}

function Invoke-Coverage {
    Write-Host "Generando reporte de cobertura..." -ForegroundColor Yellow
    python tdd_runner.py --coverage
}

function Invoke-Format {
    Write-Host "Formateando codigo..." -ForegroundColor Yellow
    black . --line-length 88
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Codigo formateado" -ForegroundColor Green
    }
}

function Invoke-Lint {
    Write-Host "Ejecutando linting..." -ForegroundColor Yellow
    flake8 .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Linting pasado" -ForegroundColor Green
    }
}

function Invoke-TypeCheck {
    Write-Host "Verificando tipos..." -ForegroundColor Yellow
    mypy . --ignore-missing-imports
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Type checking pasado" -ForegroundColor Green
    }
}

function Invoke-Security {
    Write-Host "Analisis de seguridad..." -ForegroundColor Yellow
    python tdd_runner.py --security
}

function Invoke-Quality {
    Write-Host "Verificaciones de calidad completas..." -ForegroundColor Magenta
    Invoke-Format
    Invoke-Lint
    Invoke-TypeCheck
    Invoke-Security
    Write-Host "Verificaciones de calidad completadas" -ForegroundColor Green
}

function Invoke-CI {
    Write-Host "Pipeline CI completo..." -ForegroundColor Cyan
    python tdd_runner.py --ci
}

function Invoke-PreCommit {
    Write-Host "Verificaciones pre-commit..." -ForegroundColor Yellow
    Invoke-Format
    Invoke-Lint
    Invoke-AllTests
    Write-Host "Pre-commit checks completados" -ForegroundColor Green
}

function Invoke-Clean {
    Write-Host "Limpiando archivos temporales..." -ForegroundColor Yellow
    
    # Limpiar __pycache__
    Get-ChildItem -Recurse -Name "__pycache__" | Remove-Item -Recurse -Force
    
    # Limpiar .pyc files
    Get-ChildItem -Recurse -Name "*.pyc" | Remove-Item -Force
    
    # Limpiar coverage files
    if (Test-Path "htmlcov") { Remove-Item "htmlcov" -Recurse -Force }
    if (Test-Path ".coverage") { Remove-Item ".coverage" -Force }
    
    Write-Host "Limpieza completada" -ForegroundColor Green
}

function Invoke-CleanAll {
    Write-Host "Limpieza completa..." -ForegroundColor Yellow
    Invoke-Clean
    
    # Limpiar logs
    if (Test-Path "logs") { 
        Get-ChildItem "logs\*.log" | Remove-Item -Force
    }
    
    # Limpiar reportes
    if (Test-Path "security_report.json") { Remove-Item "security_report.json" -Force }
    
    Write-Host "Limpieza completa terminada" -ForegroundColor Green
}

# Ejecutar comando basado en parámetro
switch ($Command) {
    "help" { Show-Help }
    "install" { Install-Dependencies }
    "check" { Test-Dependencies }
    "red" { Invoke-RedPhase }
    "green" { Invoke-GreenPhase }
    "refactor" { Invoke-RefactorPhase }
    "tdd-cycle" { Invoke-TDDCycle }
    "test" { Invoke-AllTests }
    "test-unit" { Invoke-UnitTests }
    "test-tdd" { Invoke-TDDTests }
    "coverage" { Invoke-Coverage }
    "format" { Invoke-Format }
    "lint" { Invoke-Lint }
    "type-check" { Invoke-TypeCheck }
    "security" { Invoke-Security }
    "quality" { Invoke-Quality }
    "ci" { Invoke-CI }
    "pre-commit" { Invoke-PreCommit }
    "clean" { Invoke-Clean }
    "clean-all" { Invoke-CleanAll }
    default { 
        Write-Host "Comando desconocido: $Command" -ForegroundColor Red
        Show-Help 
    }
}