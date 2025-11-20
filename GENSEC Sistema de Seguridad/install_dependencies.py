#!/usr/bin/env python3
"""
Instalador de Dependencias para el Sistema Anti-Keylogger
Instala automáticamente las dependencias necesarias
"""

import subprocess
import sys
import importlib.util


def install_package(package_name, import_name=None):
    """Instala un paquete si no está disponible"""
    if import_name is None:
        import_name = package_name

    try:
        # Verificar si el paquete está instalado
        spec = importlib.util.find_spec(import_name)
        if spec is not None:
            print(f"✅ {package_name} ya está instalado")
            return True
    except ImportError:
        pass

    # Instalar el paquete
    try:
        print(f"📦 Instalando {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"✅ {package_name} instalado exitosamente")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error instalando {package_name}: {e}")
        return False


def main():
    """Instala todas las dependencias necesarias"""
    print("🛡️ Instalador de Dependencias - Sistema Anti-Keylogger")
    print("=" * 60)

    # Lista de dependencias
    dependencies = [
        ("matplotlib", "matplotlib"),
        ("psutil", "psutil"),
        ("numpy", "numpy"),
    ]

    success_count = 0
    total_count = len(dependencies)

    for package_name, import_name in dependencies:
        if install_package(package_name, import_name):
            success_count += 1
        print()

    print("=" * 60)
    print(
        f"📊 Resumen: {success_count}/{total_count} dependencias instaladas correctamente"
    )

    if success_count == total_count:
        print("🎉 ¡Todas las dependencias están listas!")
        print("   Ahora puedes ejecutar el sistema con: python launcher.py")
    else:
        print("⚠️ Algunas dependencias fallaron. Intenta instalar manualmente:")
        for package_name, _ in dependencies:
            print(f"   pip install {package_name}")


if __name__ == "__main__":
    main()
