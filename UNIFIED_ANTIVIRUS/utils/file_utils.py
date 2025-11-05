"""
File Utilities - Advanced file operations for the Unified Antivirus
==================================================================

Utilidades avanzadas para manejo de archivos, incluyendo análisis de archivos,
cálculo de hashes, operaciones seguras y detección de tipos de archivo.
"""

import os
import hashlib
import shutil
import tempfile
import mimetypes
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, Tuple
import json
import zipfile
import tarfile
from datetime import datetime
import stat


class FileUtils:
    """
    Utilidades avanzadas para operaciones con archivos.

    Incluye:
    - Cálculo de hashes múltiples
    - Análisis de metadatos
    - Operaciones seguras de archivos
    - Detección de tipos MIME
    - Compresión y descompresión
    - Backup y restauración
    """

    @staticmethod
    def calculate_hash(
        file_path: Union[str, Path], algorithms: List[str] = None
    ) -> Dict[str, str]:
        """
        Calcula múltiples hashes de un archivo

        Args:
            file_path: Ruta del archivo
            algorithms: Lista de algoritmos (md5, sha1, sha256, sha512)

        Returns:
            Diccionario con los hashes calculados
        """
        if algorithms is None:
            algorithms = ["md5", "sha256"]

        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        hashers = {}
        for algo in algorithms:
            if hasattr(hashlib, algo):
                hashers[algo] = getattr(hashlib, algo)()
            else:
                raise ValueError(f"Algoritmo de hash no soportado: {algo}")

        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    for hasher in hashers.values():
                        hasher.update(chunk)

            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}

        except Exception as e:
            raise IOError(f"Error calculando hash de {file_path}: {e}")

    @staticmethod
    def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Obtiene información completa de un archivo

        Args:
            file_path: Ruta del archivo

        Returns:
            Diccionario con información del archivo
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        stat_info = file_path.stat()

        # Información básica
        info = {
            "path": str(file_path.absolute()),
            "name": file_path.name,
            "extension": file_path.suffix.lower(),
            "size_bytes": stat_info.st_size,
            "size_human": FileUtils.format_size(stat_info.st_size),
            "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            "permissions": oct(stat_info.st_mode)[-3:],
            "is_executable": os.access(file_path, os.X_OK),
            "is_readable": os.access(file_path, os.R_OK),
            "is_writable": os.access(file_path, os.W_OK),
        }

        # Tipo MIME
        mime_type, encoding = mimetypes.guess_type(str(file_path))
        info["mime_type"] = mime_type
        info["encoding"] = encoding

        # Información específica por tipo
        if file_path.suffix.lower() in [".exe", ".dll", ".sys"]:
            info["file_type"] = "executable"
            info["potentially_dangerous"] = True
        elif file_path.suffix.lower() in [".bat", ".cmd", ".ps1", ".vbs", ".js"]:
            info["file_type"] = "script"
            info["potentially_dangerous"] = True
        elif file_path.suffix.lower() in [".txt", ".log", ".conf", ".cfg"]:
            info["file_type"] = "text"
            info["potentially_dangerous"] = False
        else:
            info["file_type"] = "unknown"
            info["potentially_dangerous"] = False

        return info

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """
        Formatea tamaño en bytes a formato legible

        Args:
            size_bytes: Tamaño en bytes

        Returns:
            Tamaño formateado (ej: "1.5 MB")
        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def is_suspicious_file(file_path: Union[str, Path]) -> Tuple[bool, List[str]]:
        """
        Determina si un archivo es sospechoso basado en múltiples criterios

        Args:
            file_path: Ruta del archivo

        Returns:
            Tupla (es_sospechoso, razones)
        """
        file_path = Path(file_path)
        reasons = []

        if not file_path.exists():
            return False, ["Archivo no existe"]

        info = FileUtils.get_file_info(file_path)

        # Verificar extensión sospechosa
        suspicious_extensions = [
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".pif",
            ".vbs",
            ".js",
            ".jar",
            ".application",
            ".gadget",
            ".msi",
            ".msp",
            ".dll",
        ]

        if info["extension"] in suspicious_extensions:
            reasons.append(f"Extensión sospechosa: {info['extension']}")

        # Verificar ubicación sospechosa
        suspicious_paths = ["temp", "tmp", "appdata\\roaming", "users\\public"]
        path_str = str(file_path).lower()

        for suspicious_path in suspicious_paths:
            if suspicious_path in path_str:
                reasons.append(f"Ubicación sospechosa: {suspicious_path}")
                break

        # Verificar tamaño (archivos muy pequeños o muy grandes pueden ser sospechosos)
        if info["size_bytes"] < 1024:  # Menos de 1KB
            reasons.append("Tamaño inusualmente pequeño")
        elif info["size_bytes"] > 100 * 1024 * 1024:  # Más de 100MB
            reasons.append("Tamaño inusualmente grande")

        # Verificar nombre sospechoso
        suspicious_names = [
            "keylog",
            "logger",
            "capture",
            "spy",
            "trojan",
            "backdoor",
            "stealer",
            "rat",
            "worm",
            "virus",
            "malware",
        ]

        name_lower = file_path.name.lower()
        for suspicious_name in suspicious_names:
            if suspicious_name in name_lower:
                reasons.append(f"Nombre sospechoso contiene: {suspicious_name}")
                break

        return len(reasons) > 0, reasons

    @staticmethod
    def safe_copy(
        src: Union[str, Path], dst: Union[str, Path], overwrite: bool = False
    ) -> bool:
        """
        Copia un archivo de manera segura

        Args:
            src: Archivo origen
            dst: Archivo destino
            overwrite: Permitir sobrescribir archivo existente

        Returns:
            True si la copia fue exitosa
        """
        src_path = Path(src)
        dst_path = Path(dst)

        try:
            # Verificar archivo origen
            if not src_path.exists():
                raise FileNotFoundError(f"Archivo origen no existe: {src_path}")

            # Verificar archivo destino
            if dst_path.exists() and not overwrite:
                raise FileExistsError(f"Archivo destino ya existe: {dst_path}")

            # Crear directorio destino si no existe
            dst_path.parent.mkdir(parents=True, exist_ok=True)

            # Realizar copia
            shutil.copy2(src_path, dst_path)

            # Verificar integridad
            src_hash = FileUtils.calculate_hash(src_path, ["sha256"])["sha256"]
            dst_hash = FileUtils.calculate_hash(dst_path, ["sha256"])["sha256"]

            if src_hash != dst_hash:
                raise IOError("Error de integridad: los hashes no coinciden")

            return True

        except Exception as e:
            raise IOError(f"Error copiando archivo: {e}")

    @staticmethod
    def safe_delete(file_path: Union[str, Path], secure: bool = False) -> bool:
        """
        Elimina un archivo de manera segura

        Args:
            file_path: Ruta del archivo a eliminar
            secure: Realizar eliminación segura (sobrescribir antes de eliminar)

        Returns:
            True si la eliminación fue exitosa
        """
        file_path = Path(file_path)

        try:
            if not file_path.exists():
                return True  # Ya no existe

            if secure:
                # Sobrescribir con datos aleatorios antes de eliminar
                file_size = file_path.stat().st_size
                with open(file_path, "r+b") as f:
                    for _ in range(3):  # 3 pasadas
                        f.seek(0)
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())

            # Eliminar archivo
            file_path.unlink()
            return True

        except Exception as e:
            raise IOError(f"Error eliminando archivo: {e}")

    @staticmethod
    def create_backup(
        file_path: Union[str, Path], backup_dir: Union[str, Path] = None
    ) -> Path:
        """
        Crea backup de un archivo

        Args:
            file_path: Archivo a respaldar
            backup_dir: Directorio de backup (None para usar directorio del archivo)

        Returns:
            Ruta del archivo de backup creado
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no existe: {file_path}")

        # Determinar directorio de backup
        if backup_dir is None:
            backup_dir = file_path.parent / "backups"
        else:
            backup_dir = Path(backup_dir)

        backup_dir.mkdir(parents=True, exist_ok=True)

        # Generar nombre de backup único
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
        backup_path = backup_dir / backup_name

        # Crear backup
        FileUtils.safe_copy(file_path, backup_path)

        return backup_path

    @staticmethod
    def find_files(
        directory: Union[str, Path],
        pattern: str = "*",
        recursive: bool = True,
        max_size: int = None,
    ) -> List[Path]:
        """
        Busca archivos que coincidan con un patrón

        Args:
            directory: Directorio de búsqueda
            pattern: Patrón de archivos (wildcards)
            recursive: Búsqueda recursiva
            max_size: Tamaño máximo de archivo en bytes

        Returns:
            Lista de archivos encontrados
        """
        directory = Path(directory)

        if not directory.exists():
            raise FileNotFoundError(f"Directorio no existe: {directory}")

        if recursive:
            files = directory.rglob(pattern)
        else:
            files = directory.glob(pattern)

        # Filtrar solo archivos (no directorios)
        result = []
        for file_path in files:
            if file_path.is_file():
                # Aplicar filtro de tamaño si se especifica
                if max_size is None or file_path.stat().st_size <= max_size:
                    result.append(file_path)

        return result

    @staticmethod
    def compress_files(
        files: List[Union[str, Path]],
        output_path: Union[str, Path],
        format: str = "zip",
    ) -> bool:
        """
        Comprime una lista de archivos

        Args:
            files: Lista de archivos a comprimir
            output_path: Ruta del archivo comprimido
            format: Formato de compresión ('zip', 'tar', 'tar.gz')

        Returns:
            True si la compresión fue exitosa
        """
        output_path = Path(output_path)

        try:
            if format == "zip":
                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for file_path in files:
                        file_path = Path(file_path)
                        if file_path.exists():
                            zf.write(file_path, file_path.name)

            elif format in ["tar", "tar.gz"]:
                mode = "w:gz" if format == "tar.gz" else "w"
                with tarfile.open(output_path, mode) as tf:
                    for file_path in files:
                        file_path = Path(file_path)
                        if file_path.exists():
                            tf.add(file_path, file_path.name)

            else:
                raise ValueError(f"Formato no soportado: {format}")

            return True

        except Exception as e:
            raise IOError(f"Error comprimiendo archivos: {e}")

    @staticmethod
    def get_directory_size(directory: Union[str, Path]) -> Dict[str, Any]:
        """
        Calcula el tamaño total de un directorio

        Args:
            directory: Directorio a analizar

        Returns:
            Diccionario con información del directorio
        """
        directory = Path(directory)

        if not directory.exists():
            raise FileNotFoundError(f"Directorio no existe: {directory}")

        total_size = 0
        file_count = 0
        dir_count = 0

        for item in directory.rglob("*"):
            if item.is_file():
                file_count += 1
                try:
                    total_size += item.stat().st_size
                except (OSError, IOError):
                    # Archivo inaccesible, continuar
                    pass
            elif item.is_dir():
                dir_count += 1

        return {
            "path": str(directory.absolute()),
            "total_size_bytes": total_size,
            "total_size_human": FileUtils.format_size(total_size),
            "file_count": file_count,
            "directory_count": dir_count,
        }

    @staticmethod
    def clean_temp_files(
        temp_dir: Union[str, Path] = None, older_than_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Limpia archivos temporales

        Args:
            temp_dir: Directorio temporal (None para usar sistema)
            older_than_hours: Eliminar archivos más antiguos que N horas

        Returns:
            Estadísticas de limpieza
        """
        if temp_dir is None:
            temp_dir = Path(tempfile.gettempdir())
        else:
            temp_dir = Path(temp_dir)

        cutoff_time = datetime.now().timestamp() - (older_than_hours * 3600)

        deleted_count = 0
        deleted_size = 0
        errors = []

        try:
            for item in temp_dir.iterdir():
                try:
                    if item.is_file() and item.stat().st_mtime < cutoff_time:
                        size = item.stat().st_size
                        item.unlink()
                        deleted_count += 1
                        deleted_size += size
                except (OSError, IOError) as e:
                    errors.append(f"Error eliminando {item}: {e}")

        except Exception as e:
            errors.append(f"Error accediendo a directorio temporal: {e}")

        return {
            "deleted_files": deleted_count,
            "deleted_size_bytes": deleted_size,
            "deleted_size_human": FileUtils.format_size(deleted_size),
            "errors": errors,
        }
