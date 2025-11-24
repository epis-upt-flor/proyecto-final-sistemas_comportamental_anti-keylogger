# 🛡️ GENSEC Frontend - Interfaz Gráfica Profesional

Este directorio contiene toda la lógica de presentación y la interfaz gráfica de usuario (GUI) para el sistema GENSEC. Está construido utilizando **Dear PyGui**, un framework moderno que utiliza la GPU para renderizar gráficos de alto rendimiento.

## 📂 Estructura del Directorio

A continuación se detalla el propósito de cada archivo y carpeta dentro de `frontend/`:

### 📄 Archivos Principales

*   **`main.py`**: 
    *   **Punto de entrada principal** de la aplicación gráfica.
    *   Inicializa el contexto de Dear PyGui.
    *   Configura la ventana principal, el viewport y el bucle de renderizado.
    *   Orquesta la carga de componentes y temas.

*   **`launcher.py`**: 
    *   Script de **auto-instalación y lanzamiento**.
    *   Verifica que el entorno Python sea compatible.
    *   Instala automáticamente las dependencias necesarias (`requirements.txt`).
    *   Comprueba la disponibilidad de aceleración GPU.
    *   Inicia `main.py` si todas las verificaciones pasan.

*   **`requirements.txt`**: 
    *   Lista de bibliotecas Python específicas para el frontend (ej. `dearpygui`, `matplotlib`, `psutil`).

### � Carpetas de Componentes

*   **`components/`**: Módulos reutilizables de la interfaz.
    *   `dashboard.py`: Panel principal con métricas generales y estado del sistema.
    *   `realtime_monitor.py`: Gráficos en tiempo real de CPU, RAM y Red.
    *   `threat_viewer.py`: Tabla interactiva para visualizar y gestionar amenazas detectadas.
    *   `settings.py`: Panel de configuración para ajustar parámetros del antivirus.
    *   `logs_viewer.py`: Visor de registros del sistema.

*   **`themes/`**: Estilos y personalización visual.
    *   `dark_theme.py`: Definición del tema oscuro "Cybersecurity" (paleta de colores, estilos de widgets, redondeo de bordes).
    *   `fonts.py` (si existe): Gestión de tipografías personalizadas.

*   **`utils/`**: Utilidades auxiliares.
    *   `performance_monitor.py`: Clase para medir los FPS y el rendimiento de la propia interfaz.
    *   `async_helper.py`: Ayudas para manejar la comunicación asíncrona con el backend sin congelar la UI.

*   **`assets/`** (o raíz): Recursos estáticos.
    *   `clases.png`: Diagrama de clases o recurso visual de documentación.

## � Características Técnicas

*   **Aceleración GPU**: Utiliza OpenGL 3.3+ a través de Dear PyGui para una interfaz fluida (>60 FPS).
*   **Arquitectura Desacoplada**: El frontend corre en su propio hilo y se comunica con el backend (núcleo del antivirus) de forma asíncrona. Esto asegura que la interfaz nunca se congele, incluso si el antivirus está procesando una carga pesada.
*   **Visualización de Datos**: Integración con `matplotlib` y capacidades nativas de ploteo para gráficos de alto rendimiento.

## 🛠️ Cómo Ejecutar

Para iniciar la interfaz gráfica, se recomienda usar el launcher automático:

```bash
cd frontend
python launcher.py
```

Si prefieres ejecutarlo manualmente (asegúrate de tener las dependencias instaladas):

```bash
cd frontend
pip install -r requirements.txt
python main.py
```