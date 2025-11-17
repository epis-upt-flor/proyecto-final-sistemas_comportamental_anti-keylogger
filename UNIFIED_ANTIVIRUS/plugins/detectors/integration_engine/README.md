# Integration Engine Plugin

## Descripción
Plugin que integra **TDD (Test-Driven Development)**, **IAST (Interactive Application Security Testing)** y **MDSD (Model-Driven Software Development)** en tiempo real con el sistema antivirus.

## Funcionalidades

### 🧪 TDD Integration
- Ejecuta tests automáticamente cada 60 segundos
- Verifica API hooking detection
- Valida detección de puertos sospechosos
- Genera logs detallados en `logs/tdd_integration.log`

### 🛡️ IAST Security
- Análisis de vulnerabilidades cada 45 segundos
- Detecta SQL Injection, XSS, Command Injection
- Escaneo de seguridad en tiempo real
- Logs en `logs/iast_security.log`

### 🏗️ MDSD Generator
- Generación automática de código cada 2 minutos
- Ejecuta workflow engine y simple generator
- Crea templates para nuevos detectores
- Logs en `logs/mdsd_generator.log`

## Configuración

```json
{
    "tdd_config": {
        "enabled": true,
        "test_interval": 60
    },
    "iast_config": {
        "enabled": true, 
        "scan_interval": 45
    },
    "mdsd_config": {
        "enabled": true,
        "generation_interval": 120
    }
}
```

## Uso
El plugin se activa automáticamente cuando el sistema antivirus se inicia y ejecuta todas las integraciones en paralelo con los detectores principales.