"""
Antivirus Professional - Production Launcher
==========================================

Launcher optimizado para producción que excluye archivos de desarrollo.
Ejecuta solo los componentes core del sistema antivirus.
"""

import sys
import os
from pathlib import Path

def check_production_environment():
    """Verificar que el entorno de producción esté correcto"""
    
    print("🛡️ Antivirus Professional - Production Mode")
    print("=" * 50)
    
    # Verificar estructura core
    required_dirs = [
        'core',
        'plugins', 
        'frontend',
        'config',
        'utils',
        'models'
    ]
    
    missing_dirs = []
    for directory in required_dirs:
        if not Path(directory).exists():
            missing_dirs.append(directory)
    
    if missing_dirs:
        print(f"❌ Directorios core faltantes: {missing_dirs}")
        return False
    
    # Verificar archivos esenciales
    required_files = [
        'frontend/main.py',
        'core/__init__.py',
        'requirements.txt'
    ]
    
    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Archivos core faltantes: {missing_files}")
        return False
    
    print("✅ Estructura de producción verificada")
    return True

def install_production_dependencies():
    """Instalar solo dependencias de producción"""
    
    print("\n📦 Instalando dependencias de producción...")
    
    try:
        import subprocess
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Dependencias instaladas correctamente")
            return True
        else:
            print(f"❌ Error instalando dependencias: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error en instalación: {e}")
        return False

def start_production_antivirus():
    """Iniciar el sistema antivirus en modo producción"""
    
    print("\n🚀 Iniciando Antivirus Professional...")
    
    try:
        # Agregar directorio actual al path
        current_dir = Path(__file__).parent.absolute()
        sys.path.insert(0, str(current_dir))
        
        # Importar y ejecutar la interfaz principal
        from frontend.main import AntivirusProfessionalUI
        
        # Crear y ejecutar la aplicación
        app = AntivirusProfessionalUI()
        app.run()
        
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        print("💡 Asegúrate de que todos los módulos core estén disponibles")
        return False
        
    except Exception as e:
        print(f"❌ Error iniciando aplicación: {e}")
        return False
    
    return True

def main():
    """Función principal del launcher de producción"""
    
    # Cambiar al directorio del script
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)
    
    # Verificar entorno
    if not check_production_environment():
        print("\n❌ Entorno de producción no válido")
        print("💡 Ejecuta desde el directorio root del proyecto")
        return 1
    
    # Instalar dependencias
    if not install_production_dependencies():
        print("\n❌ Fallo en instalación de dependencias")
        return 1
    
    # Iniciar aplicación
    if not start_production_antivirus():
        print("\n❌ Fallo iniciando aplicación")
        return 1
    
    print("\n✅ Antivirus Professional ejecutado correctamente")
    return 0

if __name__ == "__main__":
    exit_code = main()
    
    if exit_code != 0:
        print("\n" + "=" * 50)
        print("❌ EJECUCIÓN FALLIDA")
        print("📧 Contacta soporte si el problema persiste")
        
    sys.exit(exit_code)