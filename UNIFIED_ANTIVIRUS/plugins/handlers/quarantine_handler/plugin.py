"""
Quarantine Handler Plugin
========================

Plugin para gestionar la cuarentena de archivos sospechosos y maliciosos.
Proporciona aislamiento seguro, restauración y análisis de archivos en cuarentena.
"""

import os
import shutil
import json
import hashlib
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import zipfile
import tempfile

# Agregar directorio raíz al path
import sys
from pathlib import Path

current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from core.base_plugin import BasePlugin
from core.interfaces import HandlerPluginInterface


class QuarantineHandlerPlugin(BasePlugin, HandlerPluginInterface):
    """Handler para gestión de cuarentena de archivos"""

    def __init__(self, config_path: str = None):
        super().__init__("QuarantineHandler", "1.0.0")

        # Configuración del plugin
        self.config_path = config_path or Path(__file__).parent / "config.json"
        self.config = self._load_config()

        # Directorio de cuarentena
        self.quarantine_dir = Path(
            self.config.get("quarantine_directory", "quarantine")
        )
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Base de datos de archivos en cuarentena
        self.quarantine_db_path = self.quarantine_dir / "quarantine_db.json"
        self.quarantine_db = self._load_quarantine_db()

        # Lock para operaciones thread-safe
        self.db_lock = threading.Lock()

        # Estadísticas
        self.stats = {
            "files_quarantined": 0,
            "files_restored": 0,
            "files_deleted": 0,
            "total_size_quarantined": 0,
            "session_start": datetime.now(),
        }

        # Configurar logging
        import logging

        self.logger = logging.getLogger(f"plugins.handlers.{self.name.lower()}")
        self.logger.setLevel(logging.INFO)

        self.logger.info(
            f"[QUARANTINE] Plugin inicializado - Directorio: {self.quarantine_dir}"
        )

    def _load_config(self) -> Dict[str, Any]:
        """Cargar configuración del plugin"""
        default_config = {
            "quarantine_directory": "quarantine",
            "max_file_size": "100MB",
            "max_quarantine_size": "1GB",
            "retention_days": 30,
            "compress_files": True,
            "encrypt_files": False,
            "auto_cleanup": True,
            "allowed_extensions": [".exe", ".dll", ".scr", ".bat", ".com", ".pif"],
            "backup_before_quarantine": True,
        }

        try:
            if Path(self.config_path).exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # Merge con configuración por defecto
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.warning(f"Error cargando configuración: {e}")

        return default_config

    def _load_quarantine_db(self) -> Dict[str, Any]:
        """Cargar base de datos de cuarentena"""
        try:
            if self.quarantine_db_path.exists():
                with open(self.quarantine_db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            if hasattr(self, "logger"):
                self.logger.warning(f"Error cargando DB de cuarentena: {e}")

        return {"files": {}, "metadata": {"created": datetime.now().isoformat()}}

    def _save_quarantine_db(self):
        """Guardar base de datos de cuarentena"""
        try:
            with self.db_lock:
                with open(self.quarantine_db_path, "w", encoding="utf-8") as f:
                    json.dump(self.quarantine_db, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Error guardando DB de cuarentena: {e}")

    def handle_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Manejar eventos del sistema"""
        try:
            if event_type == "threat_detected":
                return self._handle_threat_quarantine(event_data)
            elif event_type == "file_suspicious":
                return self._handle_suspicious_file(event_data)
            elif event_type == "user_quarantine_request":
                return self._handle_user_request(event_data)
            else:
                return True  # Evento no relevante para cuarentena
        except Exception as e:
            self.logger.error(f"Error manejando evento {event_type}: {e}")
            return False

    def quarantine_file(
        self,
        file_path: str,
        reason: str = "Threat detected",
        metadata: Dict[str, Any] = None,
    ) -> bool:
        """Poner archivo en cuarentena"""
        try:
            file_path = Path(file_path)

            # Verificaciones previas
            if not file_path.exists():
                self.logger.warning(f"Archivo no existe: {file_path}")
                return False

            if not file_path.is_file():
                self.logger.warning(f"No es un archivo: {file_path}")
                return False

            # Verificar tamaño
            file_size = file_path.stat().st_size
            max_size = self._parse_size(self.config.get("max_file_size", "100MB"))
            if file_size > max_size:
                self.logger.warning(
                    f"Archivo muy grande para cuarentena: {file_size} bytes"
                )
                return False

            # Generar ID único para el archivo
            file_hash = self._calculate_file_hash(file_path)
            quarantine_id = f"{file_hash}_{int(datetime.now().timestamp())}"

            # Directorio destino en cuarentena
            quarantine_file_dir = self.quarantine_dir / quarantine_id
            quarantine_file_dir.mkdir(parents=True, exist_ok=True)

            # Copiar archivo a cuarentena
            if self.config.get("compress_files", True):
                quarantine_file_path = quarantine_file_dir / f"{file_path.name}.zip"
                success = self._compress_file(file_path, quarantine_file_path)
            else:
                quarantine_file_path = quarantine_file_dir / file_path.name
                shutil.copy2(file_path, quarantine_file_path)
                success = True

            if not success:
                return False

            # Crear metadatos
            file_metadata = {
                "quarantine_id": quarantine_id,
                "original_path": str(file_path.absolute()),
                "quarantine_path": str(quarantine_file_path),
                "file_name": file_path.name,
                "file_size": file_size,
                "file_hash": file_hash,
                "quarantine_date": datetime.now().isoformat(),
                "reason": reason,
                "status": "quarantined",
                "metadata": metadata or {},
                "compressed": self.config.get("compress_files", True),
            }

            # Backup antes de eliminar original
            if self.config.get("backup_before_quarantine", True):
                backup_path = quarantine_file_dir / f"{file_path.name}.backup"
                shutil.copy2(file_path, backup_path)
                file_metadata["backup_path"] = str(backup_path)

            # Agregar a base de datos
            with self.db_lock:
                self.quarantine_db["files"][quarantine_id] = file_metadata
                self._save_quarantine_db()

            # Eliminar archivo original
            try:
                file_path.unlink()
                self.logger.info(
                    f"Archivo puesto en cuarentena: {file_path} -> {quarantine_id}"
                )
            except Exception as e:
                self.logger.error(f"Error eliminando archivo original: {e}")
                # Marcar como no eliminado
                file_metadata["original_deleted"] = False

            # Actualizar estadísticas
            self.stats["files_quarantined"] += 1
            self.stats["total_size_quarantined"] += file_size

            return True

        except Exception as e:
            self.logger.error(f"Error poniendo archivo en cuarentena: {e}")
            return False

    def restore_file(self, quarantine_id: str, restore_path: str = None) -> bool:
        """Restaurar archivo de cuarentena"""
        try:
            if quarantine_id not in self.quarantine_db["files"]:
                self.logger.warning(f"ID de cuarentena no encontrado: {quarantine_id}")
                return False

            file_metadata = self.quarantine_db["files"][quarantine_id]

            # Determinar ruta de restauración
            if restore_path:
                restore_path = Path(restore_path)
            else:
                restore_path = Path(file_metadata["original_path"])

            # Verificar que el directorio destino existe
            restore_path.parent.mkdir(parents=True, exist_ok=True)

            # Restaurar archivo
            quarantine_file_path = Path(file_metadata["quarantine_path"])

            if file_metadata.get("compressed", False):
                success = self._decompress_file(quarantine_file_path, restore_path)
            else:
                shutil.copy2(quarantine_file_path, restore_path)
                success = True

            if success:
                # Actualizar metadatos
                file_metadata["status"] = "restored"
                file_metadata["restore_date"] = datetime.now().isoformat()
                file_metadata["restore_path"] = str(restore_path)

                with self.db_lock:
                    self._save_quarantine_db()

                self.stats["files_restored"] += 1
                self.logger.info(
                    f"Archivo restaurado: {quarantine_id} -> {restore_path}"
                )
                return True

        except Exception as e:
            self.logger.error(f"Error restaurando archivo: {e}")

        return False

    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """Eliminar archivo de cuarentena permanentemente"""
        try:
            if quarantine_id not in self.quarantine_db["files"]:
                self.logger.warning(f"ID de cuarentena no encontrado: {quarantine_id}")
                return False

            file_metadata = self.quarantine_db["files"][quarantine_id]

            # Eliminar archivos físicos
            quarantine_file_dir = Path(file_metadata["quarantine_path"]).parent
            if quarantine_file_dir.exists():
                shutil.rmtree(quarantine_file_dir)

            # Eliminar de base de datos
            with self.db_lock:
                del self.quarantine_db["files"][quarantine_id]
                self._save_quarantine_db()

            self.stats["files_deleted"] += 1
            self.logger.info(f"Archivo eliminado permanentemente: {quarantine_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error eliminando archivo de cuarentena: {e}")
            return False

    def _handle_threat_quarantine(self, threat_data: Dict[str, Any]) -> bool:
        """Manejar cuarentena por amenaza detectada"""
        file_path = threat_data.get("file_path")
        if not file_path:
            return False

        threat_type = threat_data.get("threat_type", "Unknown")
        confidence = threat_data.get("confidence", 0)

        reason = f"Threat detected: {threat_type} (confidence: {confidence:.2f})"
        return self.quarantine_file(file_path, reason, threat_data)

    def _handle_suspicious_file(self, file_data: Dict[str, Any]) -> bool:
        """Manejar archivo sospechoso"""
        file_path = file_data.get("file_path")
        if not file_path:
            return False

        reason = f"Suspicious file: {file_data.get('reason', 'Unknown reason')}"
        return self.quarantine_file(file_path, reason, file_data)

    def _handle_user_request(self, request_data: Dict[str, Any]) -> bool:
        """Manejar solicitud del usuario"""
        action = request_data.get("action")

        if action == "quarantine":
            file_path = request_data.get("file_path")
            reason = "User requested quarantine"
            return self.quarantine_file(file_path, reason)
        elif action == "restore":
            quarantine_id = request_data.get("quarantine_id")
            return self.restore_file(quarantine_id)
        elif action == "delete":
            quarantine_id = request_data.get("quarantine_id")
            return self.delete_quarantined_file(quarantine_id)

        return False

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calcular hash del archivo"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _compress_file(self, source_path: Path, dest_path: Path) -> bool:
        """Comprimir archivo"""
        try:
            with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(source_path, source_path.name)
            return True
        except Exception as e:
            self.logger.error(f"Error comprimiendo archivo: {e}")
            return False

    def _decompress_file(self, zip_path: Path, dest_path: Path) -> bool:
        """Descomprimir archivo"""
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Extraer primer archivo del zip
                names = zf.namelist()
                if names:
                    with zf.open(names[0]) as source, open(dest_path, "wb") as dest:
                        dest.write(source.read())
            return True
        except Exception as e:
            self.logger.error(f"Error descomprimiendo archivo: {e}")
            return False

    def _parse_size(self, size_str: str) -> int:
        """Convertir string de tamaño a bytes"""
        size_str = size_str.upper()
        if size_str.endswith("KB"):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith("MB"):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith("GB"):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

    def get_handler_status(self) -> Dict[str, Any]:
        """Obtener estado del handler"""
        total_files = len(self.quarantine_db["files"])
        quarantined_files = len(
            [
                f
                for f in self.quarantine_db["files"].values()
                if f["status"] == "quarantined"
            ]
        )

        return {
            "active": True,
            "quarantine_directory": str(self.quarantine_dir),
            "total_files": total_files,
            "quarantined_files": quarantined_files,
            "files_quarantined_session": self.stats["files_quarantined"],
            "files_restored_session": self.stats["files_restored"],
            "files_deleted_session": self.stats["files_deleted"],
            "total_size_quarantined": self.stats["total_size_quarantined"],
            "session_duration": str(datetime.now() - self.stats["session_start"]),
        }

    def get_quarantined_files(self) -> List[Dict[str, Any]]:
        """Obtener lista de archivos en cuarentena"""
        return [
            {**metadata, "quarantine_id": qid}
            for qid, metadata in self.quarantine_db["files"].items()
            if metadata["status"] == "quarantined"
        ]

    def get_file_info(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Obtener información de un archivo en cuarentena"""
        return self.quarantine_db["files"].get(quarantine_id)

    def cleanup_old_files(self, days: int = None) -> int:
        """Limpiar archivos antiguos de cuarentena"""
        days = days or self.config.get("retention_days", 30)
        cutoff_date = datetime.now() - timedelta(days=days)
        cleaned = 0

        try:
            files_to_delete = []

            for quarantine_id, file_metadata in self.quarantine_db["files"].items():
                quarantine_date = datetime.fromisoformat(
                    file_metadata["quarantine_date"]
                )
                if quarantine_date < cutoff_date:
                    files_to_delete.append(quarantine_id)

            for quarantine_id in files_to_delete:
                if self.delete_quarantined_file(quarantine_id):
                    cleaned += 1

        except Exception as e:
            self.logger.error(f"Error limpiando archivos antiguos: {e}")

        return cleaned


def create_plugin(config_path: str = None) -> QuarantineHandlerPlugin:
    """Función factory para crear el plugin"""
    return QuarantineHandlerPlugin(config_path)


if __name__ == "__main__":
    # Test básico del plugin
    quarantine = QuarantineHandlerPlugin()

    print(f"Estado: {quarantine.get_handler_status()}")
    print(f"Archivos en cuarentena: {len(quarantine.get_quarantined_files())}")

    # Test de cuarentena (si hay archivos de prueba)
    # quarantine.quarantine_file("test_file.txt", "Test quarantine")
