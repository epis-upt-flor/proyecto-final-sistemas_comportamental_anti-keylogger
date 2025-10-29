"""
System Utilities - Advanced system operations for the Unified Antivirus
======================================================================

Utilidades avanzadas para operaciones del sistema, incluyendo información
del sistema, gestión de procesos, monitoreo de recursos y operaciones de red.
"""

import os
import sys
import psutil
import platform
import subprocess
import socket
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import threading
import queue
import json


class SystemUtils:
    """
    Utilidades avanzadas para operaciones del sistema.
    
    Incluye:
    - Información del sistema y hardware
    - Gestión de procesos
    - Monitoreo de recursos
    - Operaciones de red
    - Comandos del sistema
    - Detección de virtualización
    """
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """
        Obtiene información completa del sistema
        
        Returns:
            Diccionario con información del sistema
        """
        try:
            # Información básica del sistema
            info = {
                'platform': {
                    'system': platform.system(),
                    'release': platform.release(),
                    'version': platform.version(),
                    'machine': platform.machine(),
                    'processor': platform.processor(),
                    'architecture': platform.architecture(),
                    'node': platform.node()
                },
                'python': {
                    'version': platform.python_version(),
                    'implementation': platform.python_implementation(),
                    'executable': sys.executable
                },
                'cpu': {
                    'count_physical': psutil.cpu_count(logical=False),
                    'count_logical': psutil.cpu_count(logical=True),
                    'frequency_current': psutil.cpu_freq().current if psutil.cpu_freq() else None,
                    'frequency_max': psutil.cpu_freq().max if psutil.cpu_freq() else None
                },
                'memory': {
                    'total_bytes': psutil.virtual_memory().total,
                    'total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                    'available_bytes': psutil.virtual_memory().available,
                    'available_gb': round(psutil.virtual_memory().available / (1024**3), 2),
                    'percent_used': psutil.virtual_memory().percent
                },
                'disk': [],
                'network': {
                    'hostname': socket.gethostname(),
                    'fqdn': socket.getfqdn()
                },
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'uptime_seconds': time.time() - psutil.boot_time()
            }
            
            # Información de discos
            for partition in psutil.disk_partitions():
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    info['disk'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total_bytes': disk_usage.total,
                        'total_gb': round(disk_usage.total / (1024**3), 2),
                        'used_bytes': disk_usage.used,
                        'used_gb': round(disk_usage.used / (1024**3), 2),
                        'free_bytes': disk_usage.free,
                        'free_gb': round(disk_usage.free / (1024**3), 2),
                        'percent_used': round((disk_usage.used / disk_usage.total) * 100, 1)
                    })
                except (PermissionError, OSError):
                    # Disco inaccesible, continuar
                    continue
            
            # Dirección IP local
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                info['network']['local_ip'] = s.getsockname()[0]
                s.close()
            except Exception:
                info['network']['local_ip'] = 'unknown'
            
            return info
            
        except Exception as e:
            raise RuntimeError(f"Error obteniendo información del sistema: {e}")
    
    @staticmethod
    def get_current_resources() -> Dict[str, Any]:
        """
        Obtiene el uso actual de recursos del sistema
        
        Returns:
            Diccionario con métricas de recursos
        """
        try:
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': psutil.cpu_percent(interval=1),
                    'per_core': psutil.cpu_percent(interval=1, percpu=True),
                    'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
                },
                'memory': {
                    'virtual': psutil.virtual_memory()._asdict(),
                    'swap': psutil.swap_memory()._asdict() if psutil.swap_memory() else None
                },
                'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None,
                'network_io': psutil.net_io_counters()._asdict(),
                'processes_count': len(psutil.pids()),
                'connections_count': len(psutil.net_connections())
            }
        except Exception as e:
            raise RuntimeError(f"Error obteniendo recursos actuales: {e}")
    
    @staticmethod
    def get_process_info(pid: int) -> Dict[str, Any]:
        """
        Obtiene información detallada de un proceso
        
        Args:
            pid: ID del proceso
            
        Returns:
            Diccionario con información del proceso
        """
        try:
            process = psutil.Process(pid)
            
            # Información básica
            info = {
                'pid': pid,
                'name': process.name(),
                'status': process.status(),
                'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                'cpu_percent': process.cpu_percent(),
                'memory_info': process.memory_info()._asdict(),
                'memory_percent': process.memory_percent(),
                'num_threads': process.num_threads(),
                'username': process.username() if hasattr(process, 'username') else 'unknown'
            }
            
            # Información adicional (puede fallar en algunos casos)
            try:
                info['exe'] = process.exe()
                info['cwd'] = process.cwd()
                info['cmdline'] = process.cmdline()
                info['parent_pid'] = process.ppid()
                info['children_pids'] = [child.pid for child in process.children()]
                info['connections'] = [conn._asdict() for conn in process.connections()]
                info['open_files'] = [f.path for f in process.open_files()]
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Información no disponible
                pass
            
            return info
            
        except psutil.NoSuchProcess:
            raise ValueError(f"Proceso con PID {pid} no existe")
        except Exception as e:
            raise RuntimeError(f"Error obteniendo información del proceso {pid}: {e}")
    
    @staticmethod
    def find_processes_by_name(name: str) -> List[Dict[str, Any]]:
        """
        Busca procesos por nombre
        
        Args:
            name: Nombre del proceso a buscar
            
        Returns:
            Lista de procesos encontrados
        """
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                if name.lower() in proc.info['name'].lower():
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    @staticmethod
    def kill_process(pid: int, force: bool = False) -> bool:
        """
        Termina un proceso
        
        Args:
            pid: ID del proceso
            force: Usar terminación forzada (SIGKILL)
            
        Returns:
            True si el proceso fue terminado exitosamente
        """
        try:
            process = psutil.Process(pid)
            
            if force:
                process.kill()
            else:
                process.terminate()
            
            # Esperar hasta 5 segundos a que termine
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                if not force:
                    # Intentar terminación forzada
                    process.kill()
                    process.wait(timeout=2)
            
            return not process.is_running()
            
        except psutil.NoSuchProcess:
            return True  # Ya no existe
        except Exception as e:
            raise RuntimeError(f"Error terminando proceso {pid}: {e}")
    
    @staticmethod
    def execute_command(command: Union[str, List[str]], 
                       timeout: int = 30,
                       capture_output: bool = True,
                       shell: bool = None) -> Dict[str, Any]:
        """
        Ejecuta un comando del sistema
        
        Args:
            command: Comando a ejecutar
            timeout: Timeout en segundos
            capture_output: Capturar salida del comando
            shell: Ejecutar en shell (None para auto-detectar)
            
        Returns:
            Diccionario con resultado del comando
        """
        if shell is None:
            shell = isinstance(command, str)
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                shell=shell
            )
            
            execution_time = time.time() - start_time
            
            return {
                'command': command,
                'returncode': result.returncode,
                'stdout': result.stdout if capture_output else None,
                'stderr': result.stderr if capture_output else None,
                'execution_time': execution_time,
                'success': result.returncode == 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'command': command,
                'returncode': -1,
                'stdout': None,
                'stderr': f"Command timed out after {timeout} seconds",
                'execution_time': timeout,
                'success': False
            }
        except Exception as e:
            return {
                'command': command,
                'returncode': -1,
                'stdout': None,
                'stderr': str(e),
                'execution_time': time.time() - start_time,
                'success': False
            }
    
    @staticmethod
    def check_internet_connection(host: str = "8.8.8.8", port: int = 53, timeout: int = 3) -> bool:
        """
        Verifica conexión a Internet
        
        Args:
            host: Host para probar conexión
            port: Puerto para probar conexión
            timeout: Timeout de conexión
            
        Returns:
            True si hay conexión a Internet
        """
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error:
            return False
    
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """
        Obtiene información de interfaces de red
        
        Returns:
            Lista de interfaces de red
        """
        interfaces = []
        
        for name, addresses in psutil.net_if_addrs().items():
            interface_info = {
                'name': name,
                'addresses': []
            }
            
            for addr in addresses:
                address_info = {
                    'family': addr.family.name if hasattr(addr.family, 'name') else str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                }
                interface_info['addresses'].append(address_info)
            
            # Estadísticas de la interfaz
            try:
                stats = psutil.net_if_stats()[name]
                interface_info['stats'] = {
                    'is_up': stats.isup,
                    'duplex': stats.duplex.name if hasattr(stats.duplex, 'name') else str(stats.duplex),
                    'speed': stats.speed,
                    'mtu': stats.mtu
                }
            except KeyError:
                interface_info['stats'] = None
            
            interfaces.append(interface_info)
        
        return interfaces
    
    @staticmethod
    def is_virtualized() -> Dict[str, Any]:
        """
        Detecta si el sistema está ejecutándose en una máquina virtual
        
        Returns:
            Diccionario con información de virtualización
        """
        indicators = {
            'is_virtual': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        # Verificar hardware/BIOS
        try:
            system_info = SystemUtils.get_system_info()
            
            vm_indicators = [
                'vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v',
                'parallels', 'kvm', 'virtual', 'vbox'
            ]
            
            # Verificar en diferentes campos
            text_to_check = [
                system_info['platform']['system'].lower(),
                system_info['platform']['processor'].lower(),
                system_info['platform']['node'].lower()
            ]
            
            for text in text_to_check:
                for indicator in vm_indicators:
                    if indicator in text:
                        indicators['indicators'].append(f"Found '{indicator}' in system info")
                        indicators['confidence'] += 0.3
            
            # Verificar procesos específicos de VM
            vm_processes = ['vmtoolsd', 'vboxservice', 'xenservice']
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for vm_proc in vm_processes:
                        if vm_proc in proc_name:
                            indicators['indicators'].append(f"Found VM process: {proc_name}")
                            indicators['confidence'] += 0.4
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Verificar hardware virtual
            if system_info['cpu']['count_physical'] < system_info['cpu']['count_logical']:
                if system_info['cpu']['count_logical'] % system_info['cpu']['count_physical'] == 0:
                    indicators['indicators'].append("Perfect CPU logical/physical ratio")
                    indicators['confidence'] += 0.2
            
        except Exception as e:
            indicators['indicators'].append(f"Error checking virtualization: {e}")
        
        indicators['confidence'] = min(indicators['confidence'], 1.0)
        indicators['is_virtual'] = indicators['confidence'] > 0.5
        
        return indicators
    
    @staticmethod
    def get_startup_programs() -> List[Dict[str, Any]]:
        """
        Obtiene lista de programas de inicio
        
        Returns:
            Lista de programas de inicio
        """
        startup_programs = []
        
        # Ubicaciones comunes de programas de inicio en Windows
        startup_locations = [
            Path(os.environ.get('APPDATA', '')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup',
            Path('C:') / 'ProgramData' / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
        ]
        
        for location in startup_locations:
            if location.exists():
                try:
                    for item in location.iterdir():
                        if item.is_file():
                            startup_programs.append({
                                'name': item.name,
                                'path': str(item),
                                'location': 'startup_folder',
                                'size_bytes': item.stat().st_size,
                                'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                            })
                except (PermissionError, OSError):
                    continue
        
        # En Windows, también verificar registro (simplificado)
        if platform.system() == 'Windows':
            try:
                import winreg
                
                registry_keys = [
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                ]
                
                for hkey, subkey in registry_keys:
                    try:
                        with winreg.OpenKey(hkey, subkey) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    startup_programs.append({
                                        'name': name,
                                        'path': value,
                                        'location': 'registry',
                                        'size_bytes': None,
                                        'modified': None
                                    })
                                    i += 1
                                except WindowsError:
                                    break
                    except (PermissionError, OSError, WindowsError):
                        continue
            except ImportError:
                # winreg no disponible (no Windows)
                pass
        
        return startup_programs
    
    @staticmethod
    def monitor_resources(duration: int = 60, interval: int = 1) -> Dict[str, Any]:
        """
        Monitorea recursos del sistema por un período de tiempo
        
        Args:
            duration: Duración del monitoreo en segundos
            interval: Intervalo entre mediciones en segundos
            
        Returns:
            Diccionario con estadísticas de recursos
        """
        measurements = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                measurement = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': psutil.cpu_percent(interval=None),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else None,
                    'network_io': psutil.net_io_counters()._asdict(),
                    'processes_count': len(psutil.pids())
                }
                
                measurements.append(measurement)
                time.sleep(interval)
                
            except KeyboardInterrupt:
                break
            except Exception:
                continue
        
        if not measurements:
            return {'error': 'No measurements collected'}
        
        # Calcular estadísticas
        cpu_values = [m['cpu_percent'] for m in measurements if m['cpu_percent'] is not None]
        memory_values = [m['memory_percent'] for m in measurements if m['memory_percent'] is not None]
        
        return {
            'duration': time.time() - start_time,
            'measurements_count': len(measurements),
            'cpu': {
                'min': min(cpu_values) if cpu_values else None,
                'max': max(cpu_values) if cpu_values else None,
                'avg': sum(cpu_values) / len(cpu_values) if cpu_values else None
            },
            'memory': {
                'min': min(memory_values) if memory_values else None,
                'max': max(memory_values) if memory_values else None,
                'avg': sum(memory_values) / len(memory_values) if memory_values else None
            },
            'raw_measurements': measurements
        }