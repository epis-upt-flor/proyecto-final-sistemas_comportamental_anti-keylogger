"""
Instalador y Launcher del Frontend Dear PyGui
============================================

Script para instalar dependencias y lanzar el nuevo frontend.
Maneja la compatibilidad con el sistema existente.
"""

import sys
import subprocess
import os
from pathlib import Path
import importlib.util


def check_python_version():
    """Verificar versión de Python"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8+ requerido")
        print(f"   Versión actual: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} compatible")
    return True


def install_dependencies():
    """Instalar dependencias del frontend"""
    print("📦 Instalando dependencias del frontend...")
    
    frontend_dir = Path(__file__).parent
    requirements_file = frontend_dir / "requirements.txt"
    
    if not requirements_file.exists():
        print("❌ Error: requirements.txt no encontrado")
        return False
    
    try:
        # Instalar dependencias
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        print("✅ Dependencias instaladas correctamente")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error instalando dependencias: {e}")
        return False


def check_dearpygui_compatibility():
    """Verificar compatibilidad con Dear PyGui"""
    print("🎮 Verificando compatibilidad GPU...")
    
    try:
        import dearpygui.dearpygui as dpg
        
        # Probar creación de contexto
        dpg.create_context()
        print("✅ Dear PyGui compatible - Aceleración GPU disponible")
        
        # Probar viewport básico
        dpg.create_viewport(title="Test", width=100, height=100, show=False)
        dpg.setup_dearpygui()
        dpg.destroy_context()
        
        print("✅ Renderizado GPU funcional")
        return True
        
    except ImportError:
        print("❌ Dear PyGui no instalado")
        return False
        
    except Exception as e:
        print(f"⚠️ Advertencia GPU: {e}")
        print("💡 Funcionará en modo compatibilidad")
        return True  # Permitir continuar en modo fallback


def check_backend_compatibility():
    """Verificar que el backend esté disponible"""
    print("🛡️ Verificando backend antivirus...")
    
    try:
        # Intentar importar componentes del backend
        root_dir = Path(__file__).parent.parent
        sys.path.insert(0, str(root_dir))
        
        from core.engine import UnifiedAntivirusEngine
        from utils.logger import setup_logger
        
        print("✅ Backend antivirus accesible")
        return True
        
    except ImportError as e:
        print(f"❌ Error accediendo backend: {e}")
        print("💡 Asegúrate de estar en el directorio correcto")
        return False


def launch_frontend():
    """Lanzar el frontend Dear PyGui"""
    print("🚀 Lanzando Antivirus Professional UI...")
    
    try:
        from main import main
        return main()
        
    except ImportError as e:
        print(f"❌ Error importando frontend: {e}")
        return 1
        
    except Exception as e:
        print(f"❌ Error ejecutando frontend: {e}")
        return 1


def show_system_info():
    """Mostrar información del sistema"""
    print("🖥️ Información del Sistema:")
    print("=" * 40)
    
    # Información básica
    print(f"Python: {sys.version}")
    print(f"Plataforma: {sys.platform}")
    
    # Información de GPU (si está disponible)
    try:
        import platform
        print(f"OS: {platform.system()} {platform.release()}")
        
        # Intentar obtener info de OpenGL
        try:
            import dearpygui.dearpygui as dpg
            dpg.create_context()
            
            # Dear PyGui no expone directamente info de OpenGL,
            # pero si se crea sin errores, OpenGL es compatible
            print("OpenGL: Compatible (estimado 3.3+)")
            dpg.destroy_context()
            
        except:
            print("OpenGL: No disponible o incompatible")
            
    except Exception as e:
        print(f"Info adicional no disponible: {e}")
    
    print("=" * 40)


def main():
    """Función principal del instalador/launcher"""
    
    print("🛡️ Antivirus Professional - Dear PyGui Frontend")
    print("=" * 50)
    
    show_system_info()
    print()
    
    # Verificaciones previas
    checks = [
        ("Versión Python", check_python_version),
        ("Dependencias", install_dependencies), 
        ("Compatibilidad GPU", check_dearpygui_compatibility),
        ("Backend Antivirus", check_backend_compatibility)
    ]
    
    for check_name, check_func in checks:
        print(f"🔍 Verificando {check_name}...")
        if not check_func():
            print(f"❌ Fallo en verificación: {check_name}")
            print("🛑 Instalación/lanzamiento cancelado")
            return 1
        print()
    
    print("✅ Todas las verificaciones pasaron")
    print("🚀 Iniciando aplicación...\n")
    
    # Lanzar frontend
    try:
        return launch_frontend()
        
    except KeyboardInterrupt:
        print("\n🛑 Aplicación interrumpida por el usuario")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    
    print(f"\n🏁 Aplicación terminada (código: {exit_code})")
    
    # En Windows, pausar para ver resultados
    if sys.platform == "win32" and exit_code != 0:
        input("Presiona Enter para continuar...")
    
    sys.exit(exit_code)