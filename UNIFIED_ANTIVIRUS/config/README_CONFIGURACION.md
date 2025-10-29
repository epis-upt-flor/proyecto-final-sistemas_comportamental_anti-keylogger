# ⚙️ Guía de Configuración del Sistema

## 📋 Configuración desde la Interfaz

### **Acceso al Panel de Configuración**

1. Ejecuta el sistema: `python launcher.py`
2. Ve a la pestaña **"⚙️ Configuración"**
3. Ajusta los parámetros según tus necesidades
4. Haz clic en **"✅ Aplicar Cambios"** para que los cambios tengan efecto inmediatamente
5. Opcionalmente, **"💾 Guardar Configuración"** para persistir los cambios

---

## 🔍 Secciones de Configuración

### **1. Detectores**
Configure los diferentes motores de detección:

- **Detector de Comportamiento**
  - ✅ Habilitar/deshabilitar
  - 🎯 **Umbral CPU (%)**: Límite de uso de CPU para marcar como sospechoso (10-100%)
  - 💾 **Umbral Memoria (MB)**: Límite de uso de memoria (50-1000 MB)

- **Detector de Machine Learning**
  - ✅ Habilitar/deshabilitar
  - 🎯 **Confianza ML**: Umbral de confianza para clasificar amenazas (0.1-1.0)

- **Detector de Red**
  - ✅ Habilitar/deshabilitar monitoreo de conexiones de red

### **2. Alertas**
Configure cómo recibir notificaciones:

- **Tipos de Alerta**:
  - 🖥️ **Desktop**: Ventanas emergentes en pantalla
  - 🔊 **Sonido**: Alertas audibles (requiere configuración adicional)
  - 📧 **Email**: Notificaciones por correo (requiere SMTP configurado)

- **Severidad Mínima**: Solo alertas de este nivel o superior
  - `low` → Todas las alertas
  - `medium` → Solo amenazas importantes
  - `high` → Solo amenazas serias
  - `critical` → Solo amenazas críticas

### **3. Monitoreo**
Configure la frecuencia y alcance del monitoreo:

- **Intervalo de Escaneo (seg)**: Frecuencia de análisis de procesos (1-60 segundos)
- **Monitorear Procesos Nuevos**: Detectar cuando se inician nuevos procesos
- **Seguir Árbol de Procesos**: Rastrear procesos hijos y dependencias

### **4. Interfaz**
Personalice la apariencia y comportamiento:

- **Tema**: 
  - `default` → Tema estándar del sistema
  - `dark` → Tema oscuro
  - `light` → Tema claro

- **Actualización UI (ms)**: Frecuencia de actualización de la interfaz (500-5000 ms)
- **Mostrar Gráficos**: Habilitar visualizaciones en tiempo real

### **5. Lista Blanca**
Procesos que nunca se considerarán amenazas:

- Agregue un proceso por línea
- Use nombres exactos: `proceso.exe`
- Los procesos del sistema ya están incluidos por defecto

---

## 💾 Archivos de Configuración

Los cambios se guardan automáticamente en:

| Archivo | Configuración |
|---------|---------------|
| `config/unified_config.toml` | Configuración principal del sistema |
| `config/plugins_config.json` | Configuración de detectores y plugins |
| `config/whitelist.json` | Lista de procesos de confianza |
| `config/alerts_config.json` | Configuración de alertas |
| `config/ml_config.json` | Configuración de modelos ML |
| `config/ui_config.json` | Configuración de la interfaz |

---

## 🔄 Acciones Disponibles

### **💾 Guardar Configuración**
- Persiste todos los cambios en archivos
- Los cambios sobreviven al reinicio del sistema

### **🔄 Cargar Configuración** 
- Recarga configuración desde archivos
- Útil si editó archivos manualmente

### **🔧 Valores por Defecto**
- Restaura configuración original
- ⚠️ **Advertencia**: Perderá cambios personalizados

### **✅ Aplicar Cambios**
- Aplica configuración inmediatamente
- No requiere reiniciar el sistema

---

## 🎯 Configuraciones Recomendadas

### **🏠 Uso Doméstico**
```
Detectores: Todos habilitados
CPU Threshold: 70%
Memory Threshold: 150MB
ML Confidence: 0.6
Scan Interval: 3 segundos
Alertas: Desktop habilitadas, Severidad: medium
```

### **🏢 Uso Empresarial**
```
Detectores: Todos habilitados
CPU Threshold: 85%
Memory Threshold: 200MB
ML Confidence: 0.8
Scan Interval: 1 segundo
Alertas: Desktop + Email, Severidad: high
```

### **🎮 Gaming/Performance**
```
Detectores: ML + Network habilitados
CPU Threshold: 90%
Memory Threshold: 300MB
ML Confidence: 0.9
Scan Interval: 5 segundos
Alertas: Solo críticas
```

---

## 🚀 Consejos de Optimización

### **⚡ Rendimiento**
- **Interval menor** = Mayor protección, más CPU
- **Threshold mayor** = Menos falsos positivos
- **ML Confidence alta** = Menos alertas, mayor precisión

### **🔒 Seguridad Máxima**
- Habilite todos los detectores
- Use intervalos cortos (1-2 segundos)
- Configure ML Confidence en 0.6-0.7
- Active todas las alertas

### **🎛️ Personalización**
- Agregue procesos específicos a la whitelist
- Ajuste temas según preferencia
- Configure alertas según importancia

---

## ❗ Solución de Problemas

### **Configuración no se guarda**
1. Verifique permisos de escritura en carpeta `config/`
2. Asegúrese de que los archivos no estén en uso
3. Revise logs en la consola de la aplicación

### **Cambios no aplican**
1. Haga clic en **"✅ Aplicar Cambios"** 
2. Si persiste, reinicie el sistema
3. Verifique que no hay errores en la configuración

### **Rendimiento lento**
1. Aumente el intervalo de escaneo
2. Desactive gráficos si no los necesita
3. Aumente umbrales de CPU/memoria
4. Reduzca frecuencia de actualización UI

---

¡La configuración flexible permite adaptar el sistema a sus necesidades específicas de seguridad y rendimiento! 🛡️