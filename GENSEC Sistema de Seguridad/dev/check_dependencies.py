#!/usr/bin/env python3
"""
Verificador de Dependencias - UNIFIED ANTIVIRUS + MDSD
======================================================

Verifica que todas las dependencias estén correctamente instaladas
para el sistema antivirus completo incluyendo MDSD framework.
"""

import sys
from importlib import import_module


def check_dependency(module_name, friendly_name, category):
    """Verifica una dependencia específica"""
    try:
        module = import_module(module_name)
        version = getattr(module, "__version__", "N/A")
        print(f"✅ {friendly_name}: v{version}")
        return True
    except ImportError as e:
        print(f"❌ {friendly_name}: NO INSTALADO - {e}")
        return False
    except Exception as e:
        print(f"⚠️ {friendly_name}: ERROR - {e}")
        return False


def main():
    """Verificación completa de dependencias"""

    print("🔍 UNIFIED ANTIVIRUS - Verificador de Dependencias")
    print("=" * 60)

    # Dependencias Core del Antivirus
    print("\n📡 DEPENDENCIAS CORE DEL ANTIVIRUS:")
    core_deps = [
        ("psutil", "PSUtil (Monitoreo procesos)"),
        ("watchdog", "Watchdog (Monitoreo archivos)"),
        ("toml", "TOML (Configuraciones)"),
        ("onnxruntime", "ONNX Runtime (ML)"),
        ("numpy", "NumPy (Cálculos)"),
        ("pandas", "Pandas (Datos)"),
        ("sklearn", "Scikit-learn (ML)"),
        ("dateutil", "Python DateUtil"),
        ("requests", "Requests (HTTP)"),
    ]

    core_ok = 0
    for module, name in core_deps:
        if check_dependency(module, name, "core"):
            core_ok += 1

    # Dependencias MDSD
    print(f"\n🚀 DEPENDENCIAS MDSD FRAMEWORK:")
    mdsd_deps = [
        ("yaml", "PyYAML (Configuraciones MDSD)"),
        ("schedule", "Schedule (Workflows automáticos)"),
    ]

    mdsd_ok = 0
    for module, name in mdsd_deps:
        if check_dependency(module, name, "mdsd"):
            mdsd_ok += 1

    # Dependencias estándar de Python (deberían estar siempre)
    print(f"\n🐍 DEPENDENCIAS PYTHON ESTÁNDAR:")
    std_deps = [
        ("logging", "Logging"),
        ("threading", "Threading"),
        ("subprocess", "Subprocess"),
        ("pathlib", "Pathlib"),
        ("json", "JSON"),
        ("re", "Regular Expressions"),
        ("time", "Time"),
        ("os", "OS"),
        ("sys", "Sys"),
        ("typing", "Typing"),
    ]

    std_ok = 0
    for module, name in std_deps:
        if check_dependency(module, name, "standard"):
            std_ok += 1

    # Verificaciones específicas del sistema
    print(f"\n🧪 VERIFICACIONES DEL SISTEMA:")

    # Test MDSD
    try:
        from pathlib import Path

        mdsd_dir = Path("mdsd")
        if mdsd_dir.exists():
            print("✅ Directorio MDSD encontrado")

            # Verificar archivos clave
            key_files = [
                "mdsd/simple_generator.py",
                "mdsd/workflow_engine.py",
                "mdsd/templates/detector_template.py",
            ]

            mdsd_files_ok = 0
            for file_path in key_files:
                if Path(file_path).exists():
                    print(f"✅ {file_path}")
                    mdsd_files_ok += 1
                else:
                    print(f"❌ {file_path} - NO ENCONTRADO")

        else:
            print("❌ Directorio MDSD no encontrado")
            mdsd_files_ok = 0

    except Exception as e:
        print(f"❌ Error verificando sistema MDSD: {e}")
        mdsd_files_ok = 0

    # Resumen final
    print(f"\n" + "=" * 60)
    print("📊 RESUMEN DE VERIFICACIÓN:")
    print(f"   📡 Core Antivirus: {core_ok}/{len(core_deps)} dependencias")
    print(f"   🚀 MDSD Framework: {mdsd_ok}/{len(mdsd_deps)} dependencias")
    print(f"   🐍 Python Estándar: {std_ok}/{len(std_deps)} módulos")
    print(f"   🧪 Sistema MDSD: {mdsd_files_ok}/3 archivos clave")

    total_required = len(core_deps) + len(mdsd_deps)
    total_ok = core_ok + mdsd_ok

    if total_ok == total_required and mdsd_files_ok >= 3:
        print(f"\n🎉 SISTEMA COMPLETAMENTE FUNCIONAL!")
        print(f"   ✅ Todas las dependencias instaladas")
        print(f"   ✅ MDSD Framework disponible")
        print(f"\n🚀 Comandos disponibles:")
        print(f"   python mdsd/simple_generator.py    # Generar detectores")
        print(f"   python mdsd/workflow_engine.py     # Workflows automáticos")
        print(f"   python test_mdsd_integration.py    # Test integración")
        return 0
    else:
        print(f"\n⚠️ SISTEMA PARCIALMENTE FUNCIONAL")
        if total_ok < total_required:
            missing = total_required - total_ok
            print(f"   ❌ Faltan {missing} dependencias")
            print(f"   💡 Ejecutar: pip install PyYAML schedule")

        if mdsd_files_ok < 3:
            print(f"   ❌ Sistema MDSD incompleto")
            print(f"   💡 Verificar archivos en directorio mdsd/")

        return 1


if __name__ == "__main__":
    sys.exit(main())
