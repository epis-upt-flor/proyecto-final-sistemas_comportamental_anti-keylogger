# 🛠️ Carpeta `/utils` - Utilidades del Sistema

## Descripción General

La carpeta `utils/` contiene módulos de **utilidades reutilizables** que proporcionan funcionalidad común a todos los componentes del sistema. Estas utilidades encapsulan operaciones frecuentes como logging, seguridad, gestión del sistema y manipulación de archivos.

## 📁 Archivos de Utilidades

```
utils/
├── __init__.py
├── logger.py           # Sistema de logging avanzado
├── security_utils.py   # Operaciones de seguridad
├── system_utils.py     # Utilidades del sistema operativo
└── file_utils.py       # Manipulación de archivos
```

---

## 📝 `logger.py` - Sistema de Logging Avanzado

**Propósito**: Proporcionar logging estructurado y configurable para todo el sistema

**Funcionalidad**:
- Logging multi-nivel (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Rotación automática de archivos
- Múltiples formatos de salida
- Logging estructurado (JSON)
- Thread-safe
- Singleton pattern para loggers

**Descripción Técnica**:

**Clase Principal**: `Logger`

**Características**:
```python
class Logger:
    _instances: Dict[str, 'Logger']  # Singleton por nombre
    _lock: threading.Lock             # Thread safety
    
    logger: logging.Logger
    log_dir: Path
    level: int
```

**Métodos clave**:

1. **`get_logger(name, log_dir, level)` (classmethod)**:
   ```python
   # Singleton pattern - una instancia por nombre
   with cls._lock:
       if name not in cls._instances:
           cls._instances[name] = cls(name, log_dir, level)
       return cls._instances[name]
   ```

2. **`_setup_handlers()`**:
   ```python
   # Handler para archivo general (rotación)
   file_handler = RotatingFileHandler(
       f"{self.log_dir}/{self.name}.log",
       maxBytes=10*1024*1024,  # 10MB
       backupCount=5
   )
   
   # Handler para errores (archivo separado)
   error_handler = RotatingFileHandler(
       f"{self.log_dir}/{self.name}_errors.log",
       maxBytes=5*1024*1024,
       backupCount=3
   )
   error_handler.setLevel(logging.ERROR)
   
   # Handler para consola
   console_handler = StreamHandler()
   ```

3. **Formatters**:
   ```python
   # Formato detallado para archivos
   file_formatter = logging.Formatter(
       '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   
   # Formato JSON estructurado (opcional)
   json_formatter = JSONFormatter()
   ```

**Uso**:
```python
from utils.logger import Logger

logger = Logger.get_logger('my_component', 'logs', 'INFO')
logger.info("Componente iniciado")
logger.error("Error en operación", exc_info=True)
```

---

## 🔐 `security_utils.py` - Utilidades de Seguridad

**Propósito**: Operaciones criptográficas y de seguridad

**Funcionalidad**:
- Generación de tokens seguros
- Hashing de passwords (PBKDF2)
- Cifrado/descifrado de datos
- Validación de entrada
- Sanitización de datos
- Generación de hashes (SHA256, MD5)

**Descripción Técnica**:

**Clase Principal**: `SecurityUtils`

**Métodos clave**:

1. **`generate_secure_token(length)` (static)**:
   ```python
   # Genera token criptográficamente seguro
   return secrets.token_hex(length)
   ```

2. **`generate_secure_password(length, include_symbols)` (static)**:
   ```python
   # Genera contraseña fuerte
   # Asegura al menos: 1 minúscula, 1 mayúscula, 1 dígito, 1 símbolo
   characters = string.ascii_letters + string.digits
   if include_symbols:
       characters += "!@#$%^&*"
   
   password = [
       secrets.choice(string.ascii_lowercase),
       secrets.choice(string.ascii_uppercase),
       secrets.choice(string.digits)
   ]
   # ... completar con caracteres aleatorios
   secrets.SystemRandom().shuffle(password)
   return ''.join(password)
   ```

3. **`hash_password(password, salt)` (static)**:
   ```python
   # Hashea contraseña con PBKDF2
   if salt is None:
       salt = os.urandom(32)
   
   key = hashlib.pbkdf2_hmac(
       'sha256',
       password.encode('utf-8'),
       salt,
       100000  # iteraciones
   )
   
   return (base64.b64encode(key).decode('utf-8'),
           base64.b64encode(salt).decode('utf-8'))
   ```

4. **`verify_password(password, password_hash, salt)` (static)**:
   ```python
   # Verifica contraseña contra hash
   computed_hash, _ = SecurityUtils.hash_password(
       password,
       base64.b64decode(salt)
   )
   return computed_hash == password_hash
   ```

5. **`calculate_file_hash(file_path, algorithm)` (static)**:
   ```python
   # Calcula hash de archivo (SHA256, MD5, etc.)
   hash_obj = hashlib.new(algorithm)
   
   with open(file_path, 'rb') as f:
       for chunk in iter(lambda: f.read(4096), b""):
           hash_obj.update(chunk)
   
   return hash_obj.hexdigest()
   ```

6. **`encrypt_data(data, key)` / `decrypt_data(encrypted, key)` (static)**:
   ```python
   # Cifrado AES (si habilitado)
   from cryptography.fernet import Fernet
   
   f = Fernet(key)
   encrypted = f.encrypt(data.encode())
   return encrypted
   ```

7. **`sanitize_input(input_string)` (static)**:
   ```python
   # Sanitiza entrada del usuario
   # Remueve caracteres peligrosos
   # Previene inyección
   sanitized = re.sub(r'[<>&\'"()]', '', input_string)
   return sanitized.strip()
   ```

8. **`validate_file_path(path)` (static)**:
   ```python
   # Valida que ruta sea segura
   # Previene path traversal
   path = Path(path).resolve()
   
   # Verificar que no escape del directorio permitido
   if not str(path).startswith(str(allowed_directory)):
       raise SecurityError("Path traversal detected")
   
   return path
   ```

**Uso**:
```python
from utils.security_utils import SecurityUtils

# Token seguro
token = SecurityUtils.generate_secure_token(32)

# Hash de archivo
file_hash = SecurityUtils.calculate_file_hash('file.exe', 'sha256')

# Sanitizar entrada
clean_input = SecurityUtils.sanitize_input(user_input)
```

---

## 💻 `system_utils.py` - Utilidades del Sistema

**Propósito**: Operaciones relacionadas con el sistema operativo

**Funcionalidad**:
- Información del sistema (CPU, RAM, disco)
- Gestión de procesos
- Información de red
- Detección de virtualización
- Comandos del sistema
- Permisos y privilegios

**Descripción Técnica**:

**Clase Principal**: `SystemUtils`

**Métodos clave**:

1. **`get_system_info()` (static)**:
   ```python
   # Obtiene información completa del sistema
   return {
       'platform': {
           'system': platform.system(),
           'release': platform.release(),
           'version': platform.version(),
           'machine': platform.machine(),
           'processor': platform.processor()
       },
       'cpu': {
           'count_physical': psutil.cpu_count(logical=False),
           'count_logical': psutil.cpu_count(logical=True),
           'frequency': psutil.cpu_freq()
       },
       'memory': {
           'total_gb': psutil.virtual_memory().total / (1024**3),
           'available_gb': psutil.virtual_memory().available / (1024**3),
           'percent_used': psutil.virtual_memory().percent
       },
       'disk': [...],  # Info de discos
       'network': {...}  # Info de red
   }
   ```

2. **`get_process_info(pid)` (static)**:
   ```python
   # Información detallada de proceso
   proc = psutil.Process(pid)
   return {
       'pid': pid,
       'name': proc.name(),
       'exe': proc.exe(),
       'cmdline': proc.cmdline(),
       'cpu_percent': proc.cpu_percent(),
       'memory_mb': proc.memory_info().rss / (1024**2),
       'num_threads': proc.num_threads(),
       'connections': proc.connections()
   }
   ```

3. **`is_admin()` (static)**:
   ```python
   # Verifica si se ejecuta con privilegios admin
   if platform.system() == 'Windows':
       import ctypes
       return ctypes.windll.shell32.IsUserAnAdmin() != 0
   else:
       return os.geteuid() == 0
   ```

4. **`execute_command(command, timeout)` (static)**:
   ```python
   # Ejecuta comando del sistema de forma segura
   result = subprocess.run(
       command,
       capture_output=True,
       text=True,
       timeout=timeout,
       shell=False  # Seguridad: no usar shell
   )
   
   return {
       'returncode': result.returncode,
       'stdout': result.stdout,
       'stderr': result.stderr
   }
   ```

5. **`kill_process(pid, force)` (static)**:
   ```python
   # Termina proceso de forma segura
   try:
       proc = psutil.Process(pid)
       
       if force:
           proc.kill()  # SIGKILL
       else:
           proc.terminate()  # SIGTERM
       
       proc.wait(timeout=5)
       return True
   except psutil.NoSuchProcess:
       return False
   ```

6. **`is_virtualized()` (static)**:
   ```python
   # Detecta si se ejecuta en VM
   # Verifica DMI, procesos, drivers de VM
   indicators = [
       'vmware', 'virtualbox', 'qemu', 'xen', 'kvm'
   ]
   
   # Verificar manufacturer
   try:
       manufacturer = subprocess.check_output(
           ['wmic', 'computersystem', 'get', 'manufacturer']
       ).decode().lower()
       
       return any(ind in manufacturer for ind in indicators)
   except:
       return False
   ```

**Uso**:
```python
from utils.system_utils import SystemUtils

# Info del sistema
info = SystemUtils.get_system_info()
print(f"RAM: {info['memory']['total_gb']} GB")

# Verificar admin
if not SystemUtils.is_admin():
    print("Requiere permisos de administrador")

# Matar proceso
SystemUtils.kill_process(suspicious_pid, force=True)
```

---

## 📁 `file_utils.py` - Utilidades de Archivos

**Propósito**: Operaciones sobre archivos y directorios

**Funcionalidad**:
- Copia/movimiento seguro de archivos
- Eliminación segura (sobrescritura)
- Búsqueda de archivos
- Información de archivos
- Compresión/descompresión
- Verificación de integridad

**Descripción Técnica**:

**Clase Principal**: `FileUtils`

**Métodos clave**:

1. **`safe_copy(src, dst, overwrite)` (static)**:
   ```python
   # Copia archivo de forma segura
   if not overwrite and Path(dst).exists():
       raise FileExistsError(f"{dst} already exists")
   
   # Verificar espacio disponible
   if not FileUtils.has_enough_space(src, dst):
       raise IOError("Insufficient disk space")
   
   shutil.copy2(src, dst)  # Preserva metadata
   
   # Verificar integridad
   if not FileUtils.verify_copy(src, dst):
       raise IOError("Copy verification failed")
   ```

2. **`secure_delete(file_path, passes)` (static)**:
   ```python
   # Eliminación segura (DOD 5220.22-M)
   file_size = os.path.getsize(file_path)
   
   with open(file_path, 'rb+') as f:
       for _ in range(passes):
           # Sobrescribir con datos aleatorios
           f.seek(0)
           f.write(os.urandom(file_size))
           f.flush()
           os.fsync(f.fileno())
   
   # Eliminar archivo
   os.remove(file_path)
   ```

3. **`find_files(directory, pattern, recursive)` (static)**:
   ```python
   # Búsqueda de archivos con patrón
   path = Path(directory)
   
   if recursive:
       files = path.rglob(pattern)
   else:
       files = path.glob(pattern)
   
   return [str(f) for f in files if f.is_file()]
   ```

4. **`get_file_info(file_path)` (static)**:
   ```python
   # Información detallada del archivo
   stat = os.stat(file_path)
   
   return {
       'path': file_path,
       'size_bytes': stat.st_size,
       'size_mb': stat.st_size / (1024**2),
       'created': datetime.fromtimestamp(stat.st_ctime),
       'modified': datetime.fromtimestamp(stat.st_mtime),
       'accessed': datetime.fromtimestamp(stat.st_atime),
       'is_hidden': FileUtils.is_hidden(file_path),
       'extension': Path(file_path).suffix,
       'mime_type': FileUtils.get_mime_type(file_path)
   }
   ```

5. **`compress_file(file_path, output_path)` (static)**:
   ```python
   # Comprime archivo con ZIP
   with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
       zipf.write(file_path, arcname=os.path.basename(file_path))
   ```

**Uso**:
```python
from utils.file_utils import FileUtils

# Copia segura
FileUtils.safe_copy('important.dat', 'backup/important.dat')

# Búsqueda
exe_files = FileUtils.find_files('C:\\', '*.exe', recursive=True)

# Eliminación segura
FileUtils.secure_delete('sensitive.txt', passes=3)
```

---

## 🔄 Integración con el Sistema

Estas utilidades son usadas extensamente en todo el sistema:

```python
# Ejemplo en un plugin
from utils.logger import Logger
from utils.security_utils import SecurityUtils
from utils.system_utils import SystemUtils

class MyPlugin(BasePlugin):
    def initialize(self):
        # Logger
        self.logger = Logger.get_logger(self.plugin_name)
        
        # Verificar permisos
        if not SystemUtils.is_admin():
            self.logger.warning("Plugin requires admin privileges")
        
        # Calcular hash de configuración
        config_hash = SecurityUtils.calculate_file_hash(
            'config.json',
            'sha256'
        )
        self.logger.info(f"Config hash: {config_hash}")
```

## 💡 Mejores Prácticas

1. **Usar utilidades en lugar de reimplementar**: Código probado y seguro
2. **Logging apropiado**: INFO para eventos normales, ERROR para problemas
3. **Validación de entrada**: Siempre sanitizar datos del usuario
4. **Manejo de errores**: Capturar excepciones de utilidades
5. **Thread safety**: Las utilidades son thread-safe, usar sin locks adicionales

## 🧪 Testing de Utilidades

```python
# Test de logger
logger = Logger.get_logger('test', 'logs', 'DEBUG')
logger.info("Test message")
assert Path('logs/test.log').exists()

# Test de security
token = SecurityUtils.generate_secure_token(32)
assert len(token) == 64  # hex = 2 chars por byte

# Test de system
info = SystemUtils.get_system_info()
assert info['memory']['total_gb'] > 0
```

---

**Versión**: 2.0.0  
**Última actualización**: Noviembre 2025
