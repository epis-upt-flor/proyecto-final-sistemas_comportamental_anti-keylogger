"""
Security Utilities - Advanced security operations for the Unified Antivirus
==========================================================================

Utilidades avanzadas de seguridad, incluyendo cifrado, validación, análisis
de seguridad, generación segura de datos y operaciones criptográficas.
"""

import os
import hashlib
import hmac
import secrets
import base64
import json
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import re
import urllib.parse


class SecurityUtils:
    """
    Utilidades avanzadas para operaciones de seguridad.

    Incluye:
    - Cifrado y descifrado
    - Generación segura de datos
    - Validación de entrada
    - Análisis de seguridad de archivos
    - Operaciones criptográficas
    - Sanitización de datos
    """

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Genera un token seguro aleatorio

        Args:
            length: Longitud del token en bytes

        Returns:
            Token seguro en formato hexadecimal
        """
        return secrets.token_hex(length)

    @staticmethod
    def generate_secure_password(length: int = 16, include_symbols: bool = True) -> str:
        """
        Genera una contraseña segura

        Args:
            length: Longitud de la contraseña
            include_symbols: Incluir símbolos especiales

        Returns:
            Contraseña segura generada
        """
        import string

        characters = string.ascii_letters + string.digits

        if include_symbols:
            characters += "!@#$%^&*()-_=+[]{}|;:,.<>?"

        # Asegurar que tenga al menos un carácter de cada tipo
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]

        if include_symbols:
            password.append(secrets.choice("!@#$%^&*"))

        # Completar con caracteres aleatorios
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))

        # Mezclar la contraseña
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[str, str]:
        """
        Hashea una contraseña con sal

        Args:
            password: Contraseña a hashear
            salt: Sal opcional (se genera automáticamente si no se proporciona)

        Returns:
            Tupla (hash, salt_base64)
        """
        if salt is None:
            salt = os.urandom(32)

        # Usar PBKDF2 con SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000
        )  # 100,000 iteraciones

        return (
            base64.b64encode(password_hash).decode("ascii"),
            base64.b64encode(salt).decode("ascii"),
        )

    @staticmethod
    def verify_password(password: str, hash_b64: str, salt_b64: str) -> bool:
        """
        Verifica una contraseña contra su hash

        Args:
            password: Contraseña a verificar
            hash_b64: Hash en base64
            salt_b64: Sal en base64

        Returns:
            True si la contraseña es correcta
        """
        try:
            salt = base64.b64decode(salt_b64.encode("ascii"))
            stored_hash = base64.b64decode(hash_b64.encode("ascii"))

            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, 100000
            )

            return hmac.compare_digest(stored_hash, password_hash)

        except Exception:
            return False

    @staticmethod
    def encrypt_data(data: Union[str, bytes], key: bytes) -> str:
        """
        Cifra datos usando AES (requiere cryptography library)

        Args:
            data: Datos a cifrar
            key: Clave de cifrado (32 bytes para AES-256)

        Returns:
            Datos cifrados en base64
        """
        try:
            from cryptography.fernet import Fernet

            # Si la clave no es de Fernet, crear una a partir del hash
            if len(key) != 44:  # Longitud de clave Fernet
                key_hash = hashlib.sha256(key).digest()
                key = base64.urlsafe_b64encode(key_hash)

            f = Fernet(key)

            if isinstance(data, str):
                data = data.encode("utf-8")

            encrypted_data = f.encrypt(data)
            return base64.b64encode(encrypted_data).decode("ascii")

        except ImportError:
            raise RuntimeError("cryptography library not available for encryption")
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}")

    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> bytes:
        """
        Descifra datos usando AES

        Args:
            encrypted_data: Datos cifrados en base64
            key: Clave de descifrado

        Returns:
            Datos descifrados
        """
        try:
            from cryptography.fernet import Fernet

            # Si la clave no es de Fernet, crear una a partir del hash
            if len(key) != 44:  # Longitud de clave Fernet
                key_hash = hashlib.sha256(key).digest()
                key = base64.urlsafe_b64encode(key_hash)

            f = Fernet(key)

            encrypted_bytes = base64.b64decode(encrypted_data.encode("ascii"))
            return f.decrypt(encrypted_bytes)

        except ImportError:
            raise RuntimeError("cryptography library not available for decryption")
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {e}")

    @staticmethod
    def calculate_file_integrity(file_path: Union[str, Path]) -> Dict[str, str]:
        """
        Calcula múltiples hashes para verificar integridad de archivo

        Args:
            file_path: Ruta del archivo

        Returns:
            Diccionario con diferentes hashes
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        hashers = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512(),
        }

        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    for hasher in hashers.values():
                        hasher.update(chunk)

            return {name: hasher.hexdigest() for name, hasher in hashers.items()}

        except Exception as e:
            raise IOError(f"Error calculando integridad de {file_path}: {e}")

    @staticmethod
    def verify_file_integrity(
        file_path: Union[str, Path], expected_hashes: Dict[str, str]
    ) -> Dict[str, bool]:
        """
        Verifica integridad de archivo contra hashes esperados

        Args:
            file_path: Ruta del archivo
            expected_hashes: Diccionario con hashes esperados

        Returns:
            Diccionario con resultados de verificación
        """
        current_hashes = SecurityUtils.calculate_file_integrity(file_path)

        results = {}
        for hash_type, expected_hash in expected_hashes.items():
            if hash_type in current_hashes:
                results[hash_type] = current_hashes[hash_type] == expected_hash.lower()
            else:
                results[hash_type] = False

        return results

    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> str:
        """
        Sanitiza un nombre de archivo para seguridad

        Args:
            filename: Nombre de archivo a sanitizar
            max_length: Longitud máxima permitida

        Returns:
            Nombre de archivo sanitizado
        """
        # Caracteres peligrosos en nombres de archivo
        dangerous_chars = r'[<>:"/\\|?*\x00-\x1f]'

        # Reemplazar caracteres peligrosos
        sanitized = re.sub(dangerous_chars, "_", filename)

        # Remover espacios al inicio y final
        sanitized = sanitized.strip()

        # Evitar nombres reservados en Windows
        reserved_names = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }

        name_without_ext = Path(sanitized).stem.upper()
        if name_without_ext in reserved_names:
            sanitized = f"_{sanitized}"

        # Truncar si es muy largo
        if len(sanitized) > max_length:
            name = Path(sanitized).stem
            ext = Path(sanitized).suffix
            max_name_length = max_length - len(ext)
            sanitized = name[:max_name_length] + ext

        return sanitized

    @staticmethod
    def validate_url(url: str) -> Dict[str, Any]:
        """
        Valida y analiza una URL para seguridad

        Args:
            url: URL a validar

        Returns:
            Diccionario con información de validación
        """
        result = {
            "is_valid": False,
            "is_safe": False,
            "scheme": None,
            "domain": None,
            "port": None,
            "path": None,
            "warnings": [],
        }

        try:
            parsed = urllib.parse.urlparse(url)

            result["scheme"] = parsed.scheme
            result["domain"] = (
                parsed.netloc.split(":")[0] if ":" in parsed.netloc else parsed.netloc
            )
            result["port"] = parsed.port
            result["path"] = parsed.path
            result["is_valid"] = True

            # Verificaciones de seguridad

            # Esquemas permitidos
            safe_schemes = ["http", "https", "ftp", "ftps"]
            if parsed.scheme not in safe_schemes:
                result["warnings"].append(
                    f"Esquema potencialmente inseguro: {parsed.scheme}"
                )

            # IPs privadas o localhost
            if result["domain"] in ["localhost", "127.0.0.1", "0.0.0.0"]:
                result["warnings"].append("URL apunta a localhost")
            elif result["domain"].startswith("192.168.") or result["domain"].startswith(
                "10."
            ):
                result["warnings"].append("URL apunta a IP privada")

            # Puertos inusuales
            if result["port"] and result["port"] not in [80, 443, 21, 22]:
                result["warnings"].append(f"Puerto inusual: {result['port']}")

            # Caracteres sospechosos
            suspicious_chars = ["<", ">", '"', "'", "&"]
            if any(char in url for char in suspicious_chars):
                result["warnings"].append("Contiene caracteres sospechosos")

            # Dominios sospechosos (ejemplos básicos)
            suspicious_domains = ["tempmail", "guerrilla", "10minutemail"]
            if any(
                suspicious in result["domain"].lower()
                for suspicious in suspicious_domains
            ):
                result["warnings"].append("Dominio potencialmente sospechoso")

            result["is_safe"] = len(result["warnings"]) == 0

        except Exception as e:
            result["warnings"].append(f"Error parsing URL: {e}")

        return result

    @staticmethod
    def scan_text_for_threats(text: str) -> Dict[str, Any]:
        """
        Escanea texto en busca de contenido potencialmente malicioso

        Args:
            text: Texto a escanear

        Returns:
            Diccionario con resultados del escaneo
        """
        threats = []

        # Patrones de URLs sospechosas
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[^\s]+\.[a-z]{2,4}/[^\s]*'
        urls = re.findall(url_pattern, text, re.IGNORECASE)

        for url in urls:
            url_validation = SecurityUtils.validate_url(url)
            if not url_validation["is_safe"]:
                threats.append(
                    {
                        "type": "suspicious_url",
                        "content": url,
                        "warnings": url_validation["warnings"],
                    }
                )

        # Patrones de inyección SQL
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(FROM|INTO|SET|WHERE|TABLE)\b)",
            r"(\b(UNION|OR|AND)\b.*\b(SELECT|NULL)\b)",
            r"(--|#|/\*)",  # Comentarios SQL
            r"(\b(exec|execute|sp_|xp_)\b)",
        ]

        for pattern in sql_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                threats.append(
                    {
                        "type": "potential_sql_injection",
                        "content": match[0] if isinstance(match, tuple) else match,
                        "pattern": pattern,
                    }
                )

        # Patrones de scripts maliciosos
        script_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r'on\w+\s*=\s*["\'][^"\']*["\']',  # Eventos JavaScript
        ]

        for pattern in script_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                threats.append(
                    {
                        "type": "potential_script_injection",
                        "content": match,
                        "pattern": pattern,
                    }
                )

        # Patrones de comandos del sistema
        command_patterns = [
            r"\b(cmd|powershell|bash|sh)\b.*[;&|]",
            r"\b(rm|del|format|rmdir)\b\s+[^\s]+",
            r"\b(wget|curl|nc|netcat)\b",
        ]

        for pattern in command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                threats.append(
                    {
                        "type": "potential_command_injection",
                        "content": match,
                        "pattern": pattern,
                    }
                )

        return {
            "text_length": len(text),
            "threats_found": len(threats),
            "is_safe": len(threats) == 0,
            "threats": threats,
        }

    @staticmethod
    def create_secure_config(
        config_data: Dict[str, Any], encryption_key: bytes = None
    ) -> str:
        """
        Crea configuración segura cifrada

        Args:
            config_data: Datos de configuración
            encryption_key: Clave de cifrado (se genera si no se proporciona)

        Returns:
            Configuración cifrada en formato JSON base64
        """
        if encryption_key is None:
            encryption_key = os.urandom(32)

        # Convertir a JSON
        config_json = json.dumps(config_data, indent=2)

        # Cifrar
        encrypted_config = SecurityUtils.encrypt_data(config_json, encryption_key)

        # Crear estructura segura
        secure_config = {
            "version": "1.0",
            "encrypted_data": encrypted_config,
            "timestamp": datetime.now().isoformat(),
            "integrity_hash": hashlib.sha256(encrypted_config.encode()).hexdigest(),
        }

        return base64.b64encode(json.dumps(secure_config).encode()).decode("ascii")

    @staticmethod
    def load_secure_config(
        secure_config_b64: str, encryption_key: bytes
    ) -> Dict[str, Any]:
        """
        Carga configuración segura cifrada

        Args:
            secure_config_b64: Configuración segura en base64
            encryption_key: Clave de descifrado

        Returns:
            Datos de configuración descifrados
        """
        try:
            # Decodificar base64
            secure_config_json = base64.b64decode(secure_config_b64.encode()).decode(
                "ascii"
            )
            secure_config = json.loads(secure_config_json)

            # Verificar integridad
            encrypted_data = secure_config["encrypted_data"]
            expected_hash = secure_config["integrity_hash"]
            actual_hash = hashlib.sha256(encrypted_data.encode()).hexdigest()

            if actual_hash != expected_hash:
                raise ValueError(
                    "Integrity check failed - configuration may be corrupted"
                )

            # Descifrar
            decrypted_data = SecurityUtils.decrypt_data(encrypted_data, encryption_key)

            # Convertir de JSON
            return json.loads(decrypted_data.decode("utf-8"))

        except Exception as e:
            raise RuntimeError(f"Failed to load secure configuration: {e}")

    @staticmethod
    def generate_api_signature(
        method: str, url: str, body: str, secret_key: str, timestamp: str = None
    ) -> str:
        """
        Genera firma HMAC para API requests

        Args:
            method: Método HTTP
            url: URL del request
            body: Cuerpo del request
            secret_key: Clave secreta
            timestamp: Timestamp (se genera automáticamente si no se proporciona)

        Returns:
            Firma HMAC en base64
        """
        if timestamp is None:
            timestamp = str(int(datetime.now().timestamp()))

        # Crear string para firmar
        string_to_sign = f"{method.upper()}\n{url}\n{body}\n{timestamp}"

        # Generar HMAC
        signature = hmac.new(
            secret_key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256
        ).digest()

        return base64.b64encode(signature).decode("ascii")

    @staticmethod
    def verify_api_signature(
        method: str,
        url: str,
        body: str,
        secret_key: str,
        signature: str,
        timestamp: str,
        max_age: int = 300,
    ) -> bool:
        """
        Verifica firma HMAC de API request

        Args:
            method: Método HTTP
            url: URL del request
            body: Cuerpo del request
            secret_key: Clave secreta
            signature: Firma a verificar
            timestamp: Timestamp del request
            max_age: Edad máxima permitida del request en segundos

        Returns:
            True si la firma es válida
        """
        try:
            # Verificar edad del request
            request_time = int(timestamp)
            current_time = int(datetime.now().timestamp())

            if current_time - request_time > max_age:
                return False

            # Generar firma esperada
            expected_signature = SecurityUtils.generate_api_signature(
                method, url, body, secret_key, timestamp
            )

            # Comparar firmas
            return hmac.compare_digest(signature, expected_signature)

        except Exception:
            return False

    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Valida la fortaleza de una contraseña según criterios de seguridad.

        IMPLEMENTACIÓN TDD - FASE REFACTOR: Código refactorizado y generalizado.

        Criterios de validación:
        - Longitud mínima: 8 caracteres
        - Debe contener mayúsculas
        - Debe contener minúsculas
        - Debe contener números
        - Debe contener símbolos especiales

        Args:
            password: Contraseña a validar

        Returns:
            Diccionario con información de fortaleza:
            {
                'is_strong': bool,
                'score': int (0-100),
                'weaknesses': list[dict]
            }
        """
        import re

        result = {"is_strong": False, "score": 0, "weaknesses": []}

        if not password:
            result["weaknesses"].append(
                {"type": "empty", "message": "Password cannot be empty"}
            )
            return result

        score = 0
        weaknesses = []

        # 1. Longitud (25 puntos máximo)
        length = len(password)
        if length < 8:
            weaknesses.append(
                {
                    "type": "too_short",
                    "message": "Password is too short (minimum 8 characters)",
                }
            )
            score += length * 2  # 2 puntos por carácter hasta 8
        else:
            score += 25  # Puntos completos por longitud adecuada
            if length >= 12:
                score += 5  # Bonus por longitud extra

        # 2. Letras minúsculas (15 puntos)
        if re.search(r"[a-z]", password):
            score += 15
        else:
            weaknesses.append(
                {
                    "type": "missing_lowercase",
                    "message": "Password lacks lowercase letters",
                }
            )

        # 3. Letras mayúsculas (15 puntos)
        if re.search(r"[A-Z]", password):
            score += 15
        else:
            weaknesses.append(
                {
                    "type": "missing_uppercase",
                    "message": "Password lacks uppercase letters",
                }
            )

        # 4. Números (20 puntos)
        if re.search(r"[0-9]", password):
            score += 20
        else:
            weaknesses.append(
                {"type": "missing_numbers", "message": "Password lacks numbers"}
            )

        # 5. Símbolos especiales (20 puntos)
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            weaknesses.append(
                {"type": "missing_symbols", "message": "Password lacks special symbols"}
            )

        # 6. Diversidad de caracteres (10 puntos bonus)
        unique_chars = len(set(password))
        if unique_chars >= length * 0.7:  # 70% de caracteres únicos
            score += 10

        # Penalizaciones por patrones comunes
        common_patterns = [
            r"123456",
            r"qwerty",
            r"abc123",
            r"111111",
            r"000000",
            r"admin",
        ]

        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                score -= 30
                weaknesses.append(
                    {
                        "type": "common_pattern",
                        "message": f"Contains common pattern: {pattern}",
                    }
                )
                break

        # Penalización especial para "password" pero menos severa
        if "password" in password.lower():
            score -= 10
            weaknesses.append(
                {
                    "type": "common_pattern",
                    "message": "Contains common pattern: password",
                }
            )

        # Asegurar que el score esté en el rango [0, 100]
        score = max(0, min(100, score))

        # Determinar si la contraseña es fuerte
        result["score"] = score
        result["weaknesses"] = weaknesses
        result["is_strong"] = score >= 80 and len(weaknesses) == 0

        return result
