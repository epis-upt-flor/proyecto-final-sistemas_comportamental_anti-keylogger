"""
Whitelist Manager para Behavior Detector
========================================

Gestor de lista blanca que maneja procesos y directorios confiables.
Implementa Strategy Pattern para diferentes tipos de validación.
"""

import logging
import os
from typing import Dict, List, Set, Any
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class WhitelistManager:
    """
    Gestor de lista blanca para procesos confiables

    Implementa Strategy Pattern para diferentes métodos de validación
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa el gestor de lista blanca

        Args:
            config: Configuración de whitelist
        """
        self.config = config.get("whitelist", {})
        self.enabled = self.config.get("enabled", True)

        # Conjuntos de elementos permitidos
        self.allowed_processes: Set[str] = set()
        self.trusted_directories: Set[str] = set()
        self.expanded_directories: Set[str] = (
            set()
        )  # Directorios con variables expandidas

        # Configuración de comportamiento
        self.behavior_config = self.config.get("whitelist_behavior", {})
        self.skip_analysis = self.behavior_config.get(
            "skip_analysis_for_whitelisted", True
        )
        self.strict_matching = self.behavior_config.get("strict_path_matching", True)
        self.log_access = self.behavior_config.get("log_whitelisted_access", False)

        # Estadísticas
        self.stats = {
            "processes_checked": 0,
            "whitelisted_processes": 0,
            "whitelist_hits": 0,
            "whitelist_misses": 0,
            "directory_matches": 0,
            "process_name_matches": 0,
        }

        # Cargar lista blanca
        self._load_whitelist()

        logger.info(
            f"[WHITELIST] Inicializado: {len(self.allowed_processes)} procesos, {len(self.trusted_directories)} directorios"
        )

    def _load_whitelist(self):
        """Carga la configuración de lista blanca"""
        try:
            # Cargar procesos permitidos
            processes = self.config.get("allowed_processes", [])
            self.allowed_processes = {proc.lower() for proc in processes}

            # Cargar directorios confiables
            directories = self.config.get("trusted_directories", [])
            self.trusted_directories = set(directories)

            # Expandir variables de entorno en directorios
            self._expand_directory_variables()

            logger.info(
                f"[WHITELIST] Cargados {len(self.allowed_processes)} procesos y {len(self.trusted_directories)} directorios"
            )

        except Exception as e:
            logger.error(f"[WHITELIST] Error cargando configuración: {e}")
            self.enabled = False

    def _expand_directory_variables(self):
        """Expande variables de entorno en rutas de directorios"""
        self.expanded_directories.clear()

        for directory in self.trusted_directories:
            try:
                # Expandir variables como %PROGRAMFILES%, %WINDIR%, etc.
                expanded = os.path.expandvars(directory).lower().replace("\\\\", "\\")
                self.expanded_directories.add(expanded)
                logger.debug(
                    f"[WHITELIST] Directorio expandido: {directory} -> {expanded}"
                )

            except Exception as e:
                logger.warning(
                    f"[WHITELIST] Error expandiendo directorio {directory}: {e}"
                )
                # Agregar directorio original como fallback
                self.expanded_directories.add(directory.lower())

    def is_whitelisted(self, process_name: str, process_path: str = None) -> bool:
        """
        Verifica si un proceso está en la lista blanca

        Args:
            process_name: Nombre del proceso
            process_path: Ruta completa del proceso (opcional)

        Returns:
            bool: True si el proceso está permitido
        """
        self.stats["processes_checked"] += 1

        if not self.enabled:
            logger.debug("[WHITELIST] Lista blanca deshabilitada")
            return False

        # Strategy 1: Verificación por nombre de proceso
        if self._is_process_name_whitelisted(process_name):
            self.stats["whitelisted_processes"] += 1
            self.stats["whitelist_hits"] += 1
            self.stats["process_name_matches"] += 1

            if self.log_access:
                logger.info(
                    f"[WHITELIST] ✅ Proceso permitido (nombre): {process_name}"
                )

            return True

        # Strategy 2: Verificación por directorio confiable
        if process_path and self._is_path_whitelisted(process_path):
            self.stats["whitelisted_processes"] += 1
            self.stats["whitelist_hits"] += 1
            self.stats["directory_matches"] += 1

            if self.log_access:
                logger.info(
                    f"[WHITELIST] ✅ Proceso permitido (directorio): {process_name} en {process_path}"
                )

            return True

        # No está en lista blanca
        self.stats["whitelist_misses"] += 1
        logger.debug(f"[WHITELIST] ❌ Proceso NO permitido: {process_name}")
        return False

    def _is_process_name_whitelisted(self, process_name: str) -> bool:
        """Verifica si el nombre del proceso está permitido"""
        if not process_name:
            return False

        process_name_lower = process_name.lower()

        # Verificación exacta
        if process_name_lower in self.allowed_processes:
            return True

        # Verificación con patrones (si el nombre contiene wildcards)
        for allowed_process in self.allowed_processes:
            if "*" in allowed_process or "?" in allowed_process:
                # Convertir wildcard a regex
                pattern = allowed_process.replace("*", ".*").replace("?", ".")
                if re.match(f"^{pattern}$", process_name_lower):
                    return True

        return False

    def _is_path_whitelisted(self, process_path: str) -> bool:
        """Verifica si la ruta del proceso está en directorio confiable"""
        if not process_path:
            return False

        try:
            # Normalizar ruta
            normalized_path = os.path.normpath(process_path).lower()

            # Verificar contra directorios expandidos
            for trusted_dir in self.expanded_directories:
                if self.strict_matching:
                    # Verificación estricta - debe comenzar exactamente con el directorio
                    if normalized_path.startswith(trusted_dir):
                        return True
                else:
                    # Verificación flexible - buscar el directorio en cualquier parte
                    if trusted_dir in normalized_path:
                        return True

        except Exception as e:
            logger.warning(f"[WHITELIST] Error verificando ruta {process_path}: {e}")

        return False

    def add_process(self, process_name: str):
        """Agrega un proceso a la lista blanca en runtime"""
        if process_name:
            self.allowed_processes.add(process_name.lower())
            logger.info(f"[WHITELIST] Proceso agregado: {process_name}")

    def add_directory(self, directory: str):
        """Agrega un directorio a la lista blanca en runtime"""
        if directory:
            self.trusted_directories.add(directory)
            # Re-expandir variables
            try:
                expanded = os.path.expandvars(directory).lower().replace("\\\\", "\\")
                self.expanded_directories.add(expanded)
                logger.info(
                    f"[WHITELIST] Directorio agregado: {directory} -> {expanded}"
                )
            except Exception as e:
                logger.error(
                    f"[WHITELIST] Error expandiendo directorio agregado {directory}: {e}"
                )

    def remove_process(self, process_name: str):
        """Remueve un proceso de la lista blanca"""
        self.allowed_processes.discard(process_name.lower())
        logger.info(f"[WHITELIST] Proceso removido: {process_name}")

    def remove_directory(self, directory: str):
        """Remueve un directorio de la lista blanca"""
        self.trusted_directories.discard(directory)
        # También remover versión expandida
        try:
            expanded = os.path.expandvars(directory).lower().replace("\\\\", "\\")
            self.expanded_directories.discard(expanded)
            logger.info(f"[WHITELIST] Directorio removido: {directory}")
        except Exception:
            pass

    def get_allowed_processes(self) -> List[str]:
        """Obtiene lista de procesos permitidos"""
        return list(self.allowed_processes)

    def get_trusted_directories(self) -> List[str]:
        """Obtiene lista de directorios confiables"""
        return list(self.trusted_directories)

    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas de uso de la whitelist"""
        hit_rate = 0.0
        if self.stats["processes_checked"] > 0:
            hit_rate = (
                self.stats["whitelist_hits"] / self.stats["processes_checked"]
            ) * 100

        return {
            **self.stats,
            "whitelist_enabled": self.enabled,
            "hit_rate_percent": round(hit_rate, 2),
            "total_allowed_processes": len(self.allowed_processes),
            "total_trusted_directories": len(self.trusted_directories),
        }

    def reset_stats(self):
        """Reinicia las estadísticas"""
        self.stats = {
            "processes_checked": 0,
            "whitelisted_processes": 0,
            "whitelist_hits": 0,
            "whitelist_misses": 0,
            "directory_matches": 0,
            "process_name_matches": 0,
        }

    def reload_config(self, new_config: Dict[str, Any]):
        """Recarga la configuración de whitelist"""
        try:
            self.config = new_config.get("whitelist", {})
            self.enabled = self.config.get("enabled", True)

            # Limpiar listas actuales
            self.allowed_processes.clear()
            self.trusted_directories.clear()
            self.expanded_directories.clear()

            # Recargar
            self._load_whitelist()

            logger.info(
                f"[WHITELIST] Configuración recargada: {len(self.allowed_processes)} procesos, {len(self.trusted_directories)} directorios"
            )

        except Exception as e:
            logger.error(f"[WHITELIST] Error recargando configuración: {e}")

    def validate_process_batch(self, processes: List[Dict[str, str]]) -> List[bool]:
        """
        Valida un lote de procesos para optimizar performance

        Args:
            processes: Lista de dicts con 'name' y 'path'

        Returns:
            List[bool]: Lista de resultados de validación
        """
        results = []

        for proc in processes:
            is_allowed = self.is_whitelisted(proc.get("name", ""), proc.get("path", ""))
            results.append(is_allowed)

        return results

    def export_whitelist(self) -> Dict[str, Any]:
        """Exporta la configuración actual de whitelist"""
        return {
            "allowed_processes": list(self.allowed_processes),
            "trusted_directories": list(self.trusted_directories),
            "enabled": self.enabled,
            "behavior_config": self.behavior_config,
            "stats": self.get_stats(),
        }


if __name__ == "__main__":
    # Test standalone del whitelist manager
    print("🧪 Testing Whitelist Manager...")

    test_config = {
        "whitelist": {
            "enabled": True,
            "allowed_processes": ["notepad.exe", "explorer.exe", "chrome.exe"],
            "trusted_directories": ["%PROGRAMFILES%", "%WINDIR%"],
            "whitelist_behavior": {
                "skip_analysis_for_whitelisted": True,
                "strict_path_matching": True,
                "log_whitelisted_access": True,
            },
        }
    }

    manager = WhitelistManager(test_config)

    # Test casos
    test_cases = [
        ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
        ("malware.exe", "C:\\Temp\\malware.exe"),
        ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        ("suspicious.exe", None),
    ]

    for process_name, process_path in test_cases:
        result = manager.is_whitelisted(process_name, process_path)
        status = "✅ PERMITIDO" if result else "❌ BLOQUEADO"
        print(f"{status}: {process_name} ({process_path})")

    print(f"\n📊 Estadísticas: {manager.get_stats()}")
