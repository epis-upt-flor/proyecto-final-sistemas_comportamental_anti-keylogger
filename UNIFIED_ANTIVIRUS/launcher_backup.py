#!/usr/bin/env python3
"""
Unified Antivirus Launcher
=========================

Punto de entrada principal para el Sistema Anti-Keylogger Unificado.
"""

import sys
import argparse
from pathlib import Path
import threading
import queue
import time

# Agregar el directorio actual al path para imports
sys.path.insert(0, str(Path(__file__).parent))

from core import UnifiedAntivirusEngine


def parse_arguments():
    """Parsea argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="Sistema Anti-Keylogger Unificado",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python launcher.py                     # Inicia con todos los plugins
  python launcher.py --detectors-only   # Solo detectores, sin UI
  python launcher.py --ui-only          # Solo interfaz gráfica
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
        choices=["detectors", "monitors", "interfaces", "handlers"],
        help="Categorías específicas de plugins a activar",
    )

    parser.add_argument(
        "--detectors-only", action="store_true", help="Activar solo detectores (sin UI)"
    )

    parser.add_argument(
        "--ui-only", action="store_true", help="Activar solo interfaz de usuario"
    )

    parser.add_argument(
        "--no-ui", action="store_true", help="Ejecutar sin interfaz gráfica"
    )

    parser.add_argument(
        "--debug", action="store_true", help="Habilitar logging de debug"
    )

    parser.add_argument(
        "--version", action="version", version="Unified Antivirus System v1.0.0"
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
        return ["detectors", "monitors"]

    elif args.ui_only:
        return ["interfaces"]

    elif args.no_ui:
        return ["detectors", "monitors", "handlers"]

    else:
        # Default: todas las categorías
        return None


def run_headless(args, plugin_categories):
    """Ejecuta el sistema sin interfaz gráfica"""

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
        print("Sistema funcionando... (logs disponibles en logs/)")

        # Mantener sistema ejecutándose
        import time

        while engine.is_running:
            time.sleep(1)

    print("✅ Sistema detenido correctamente")
    return 0


def run_with_ui(args, plugin_categories):
    """Ejecuta el sistema con interfaz gráfica en hilo principal"""

    # Cola para comunicación entre threads
    ui_queue = queue.Queue()

    # Crear UI plugin directamente (sin engine aún)
    try:
        # Importar plugin UI directamente
        from plugins.interfaces.tkinter_ui.plugin import TkinterUIPlugin

        ui_plugin = TkinterUIPlugin()
        if not ui_plugin.initialize():
            print("❌ Error inicializando plugin UI")
            return 1

        # Configurar cola de datos
        ui_plugin.set_data_queue(ui_queue)

        # Crear engine en hilo separado
        engine_running = threading.Event()

        def start_engine():
            """Inicia el engine en hilo separado"""
            try:
                engine = UnifiedAntivirusEngine(config_path=args.config)

                with engine:
                    # Filtrar categorías para no incluir interfaces (las manejamos aparte)
                    engine_categories = [
                        cat
                        for cat in (
                            plugin_categories or ["detectors", "monitors", "handlers"]
                        )
                        if cat != "interfaces"
                    ]

                    if not engine.start_system(engine_categories):
                        ui_queue.put(("error", "Error iniciando el sistema"))
                        return

                    engine_running.set()
                    ui_queue.put(("success", "Sistema iniciado exitosamente"))

                    # Mantener sistema ejecutándose
                    while engine.is_running and engine_running.is_set():
                        try:
                            # Enviar datos a UI
                            status = engine.get_system_status()
                            ui_queue.put(("status_update", status))
                            time.sleep(1)
                        except Exception as e:
                            ui_queue.put(("error", f"Error en loop: {e}"))
                            break

            except Exception as e:
                ui_queue.put(("error", f"Error en engine: {e}"))
                import traceback

                traceback.print_exc()

        # Iniciar engine en hilo separado
        engine_thread = threading.Thread(target=start_engine, daemon=True)
        engine_thread.start()

        print("🖥️ Iniciando interfaz gráfica...")
        print("⚡ Detectores ejecutándose en segundo plano...")

        # Ejecutar UI en hilo principal (¡CLAVE!)
        ui_plugin.run_main_thread()

        return 0

    except KeyboardInterrupt:
        print("\n🛑 Interrupción del usuario detectada")
        engine_running.clear()
        return 0

    except Exception as e:
        print(f"❌ Error en UI: {e}")
        import traceback

        traceback.print_exc()
        if "engine_running" in locals():
            engine_running.clear()
        return 1


def main():
    """Función principal"""

    # Parsear argumentos
    args = parse_arguments()

    # Configurar logging
    setup_logging(args.debug)

    # Determinar categorías de plugins
    plugin_categories = determine_plugin_categories(args)

    print("🛡️  Sistema Anti-Keylogger Unificado")
    print("=" * 50)

    if plugin_categories:
        print(f"📦 Categorías activas: {', '.join(plugin_categories)}")
    else:
        print("📦 Activando todos los plugins disponibles")

    print(f"⚙️  Configuración: {args.config}")
    print()

    try:
        # Detectar si necesitamos UI
        needs_ui = not args.no_ui and not args.detectors_only
        if plugin_categories and "interfaces" not in plugin_categories:
            needs_ui = False

        if needs_ui:
            print("�️  Iniciando con interfaz gráfica (hilo principal)")
            return run_with_ui(args, plugin_categories)
        else:
            print("⚡ Iniciando sin interfaz gráfica")
            return run_headless(args, plugin_categories)

        print("✅ Sistema detenido correctamente")
        return 0

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
