#!/usr/bin/env python3
"""
Unified Antivirus Launcher - CLEAN VERSION
==========================================

Punto de entrada principal para el Sistema Anti-Keylogger Unificado.
Version sin UI - Solo backend y detectores.
"""

import sys
import argparse
from pathlib import Path
import time

# Agregar el directorio actual al path para imports
sys.path.insert(0, str(Path(__file__).parent))

from core import UnifiedAntivirusEngine


def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Sistema Anti-Keylogger Unificado - Backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python launcher.py                     # Inicia detectores completos
  python launcher.py --detectors-only   # Solo detectores de comportamiento
  python launcher.py --categories detectors monitors  # Categorías específicas
        """,
    )

    parser.add_argument(
        "--config",
        "-c",
        default="config/unified_config.toml",
        help="Archivo de configuración (default: config/unified_config.toml)",
    )

    parser.add_argument(
        "--categories",
        nargs="+",
        choices=["detectors", "monitors", "handlers"],
        help="Categorías específicas de plugins a activar",
    )

    parser.add_argument(
        "--detectors-only",
        action="store_true",
        help="Activar solo detectores (sin handlers)",
    )

    parser.add_argument(
        "--monitors-only", action="store_true", help="Activar solo monitores de sistema"
    )

    parser.add_argument(
        "--debug", action="store_true", help="Habilitar logging de debug"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Unified Antivirus System v1.0.0 - Backend Only",
    )

    return parser.parse_args()


def setup_logging(debug_mode=False):
    """Configura el sistema de logging"""
    import logging

    level = logging.DEBUG if debug_mode else logging.INFO

    # Crear directorio de logs si no existe
    Path("logs").mkdir(exist_ok=True)

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("logs/launcher.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def determine_plugin_categories(args):
    """Determina qué categorías de plugins activar según los argumentos"""

    if args.categories:
        return args.categories

    elif args.detectors_only:
        return ["detectors"]

    elif args.monitors_only:
        return ["monitors"]

    else:
        # Default: detectores y monitores (sin interfaces)
        return ["detectors", "monitors", "handlers"]


def run_backend_system(args, plugin_categories):
    """Ejecuta el sistema backend sin interfaz gráfica"""

    # Crear e inicializar engine
    engine = UnifiedAntivirusEngine(config_path=args.config)

    # Usar context manager para manejo automático de recursos
    with engine:
        if not engine.start_system(plugin_categories):
            print("❌ Error iniciando el sistema")
            return 1

        print("✅ Sistema iniciado exitosamente")
        print("📊 Estadísticas disponibles en tiempo real")
        print("🛑 Presiona Ctrl+C para detener el sistema")
        print()

        # Mostrar estado inicial
        status = engine.get_system_status()
        print(f"🔌 Plugins activos: {len(status['active_plugins'])}")

        for plugin_name in status["active_plugins"]:
            plugin_status = engine.get_plugin_status(plugin_name)
            category = plugin_status["category"]
            print(f"  ✓ {plugin_name} ({category})")

        print()
        print("🛡️ Sistema funcionando... (logs disponibles en logs/)")
        print("📈 Estadísticas cada 30 segundos...")

        # Mantener sistema ejecutándose con estadísticas periódicas
        last_stats_time = time.time()

        while engine.is_running:
            try:
                time.sleep(1)

                # Mostrar estadísticas cada 30 segundos
                current_time = time.time()
                if current_time - last_stats_time >= 30:
                    print("\n" + "=" * 50)
                    print("📊 ESTADÍSTICAS DEL SISTEMA")
                    print("=" * 50)

                    status = engine.get_system_status()
                    print(
                        f"🔌 Plugins activos: {len(status.get('active_plugins', []))}"
                    )
                    print(f"⚠️ Amenazas detectadas: {status.get('threats_detected', 0)}")
                    print(
                        f"🔍 Procesos escaneados: {status.get('processes_scanned', 0)}"
                    )

                    uptime = (
                        current_time - engine.start_time
                        if hasattr(engine, "start_time")
                        else 0
                    )
                    hours = int(uptime // 3600)
                    minutes = int((uptime % 3600) // 60)
                    print(f"⏱️ Tiempo activo: {hours:02d}:{minutes:02d}")
                    print("=" * 50 + "\n")

                    last_stats_time = current_time

            except KeyboardInterrupt:
                print("\n🛑 Interrupción del usuario detectada")
                break

    print("✅ Sistema detenido correctamente")
    return 0


def main():
    """Función principal"""

    # Parsear argumentos
    args = parse_arguments()

    # Configurar logging
    setup_logging(args.debug)

    # Determinar categorías de plugins
    plugin_categories = determine_plugin_categories(args)

    print("🛡️  Sistema Anti-Keylogger Unificado - BACKEND")
    print("=" * 50)

    if plugin_categories:
        print(f"📦 Categorías activas: {', '.join(plugin_categories)}")
    else:
        print("📦 Activando todos los plugins disponibles (backend)")

    print(f"⚙️  Configuración: {args.config}")
    print("💻 Modo: Solo Backend (sin interfaz gráfica)")
    print()

    try:
        return run_backend_system(args, plugin_categories)

    except KeyboardInterrupt:
        print("\n🛑 Interrupción del usuario detectada")
        return 0

    except Exception as e:
        print(f"❌ Error fatal: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
