#!/usr/bin/env python3
"""
Simple Backend Executor
=======================

Ejecutor directo del sistema ANTIVIRUS_PRODUCTION original.
"""

import os
import sys
from pathlib import Path


def main():
    """Ejecuta el antivirus_launcher.py del backend original"""
    print("🛡️  Ejecutando Sistema Backend Original")
    print("=" * 40)

    # Ruta al ANTIVIRUS_PRODUCTION
    current_dir = Path(__file__).parent
    backend_path = current_dir.parent / "ANTIVIRUS_PRODUCTION"

    if not backend_path.exists():
        print(f"❌ Error: No se encuentra ANTIVIRUS_PRODUCTION en {backend_path}")
        sys.exit(1)

    launcher_file = backend_path / "antivirus_launcher.py"

    if not launcher_file.exists():
        print(f"❌ Error: No se encuentra antivirus_launcher.py en {launcher_file}")
        sys.exit(1)

    print(f"📁 Backend path: {backend_path}")
    print(f"🚀 Ejecutando: {launcher_file}")
    print()

    # Cambiar directorio y ejecutar
    original_cwd = os.getcwd()

    try:
        os.chdir(backend_path)

        # Ejecutar usando subprocess
        import subprocess

        result = subprocess.run(
            [sys.executable, "antivirus_launcher.py"], capture_output=False, text=True
        )

    except KeyboardInterrupt:
        print("\n🛑 Detenido por usuario")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    main()
