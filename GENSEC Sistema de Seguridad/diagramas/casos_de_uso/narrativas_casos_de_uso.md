# Narrativas de Casos de Uso - Sistema de Seguridad Profesional

## 📋 Índice de Casos de Uso

| ID | Caso de Uso | Actor Principal | Descripción |
|----|-------------|-----------------|-------------|
| CU-01 | Escaneo en Tiempo Real | Sistema | Monitoreo continuo de amenazas |
| CU-02 | Detección de Keylogger | Sistema | Identificación de software malicioso |
| CU-03 | Cuarentena de Archivos | Usuario/Sistema | Aislamiento de archivos sospechosos |
| CU-04 | Gestión de Amenazas | Usuario | Administración de amenazas detectadas |
| CU-05 | Configuración del Sistema | Administrador | Personalización de parámetros |
| CU-06 | Análisis de Comportamiento | Sistema | Detección basada en patrones |
| CU-07 | Generación de Reportes | Usuario | Creación de informes de seguridad |
| CU-08 | Actualización de Firmas | Sistema | Mantenimiento de definiciones |
| CU-09 | Whitelist/Blacklist | Usuario | Gestión de listas de exclusión |
| CU-10 | Respuesta a Incidentes | Sistema | Acciones automáticas ante amenazas |

---

## 🎯 CU-01: Escaneo en Tiempo Real

### **Descripción General**
El sistema realiza monitoreo continuo de procesos, archivos y actividad de red para detectar amenazas en tiempo real.

### **Actores**
- **Principal:** Sistema de Seguridad
- **Secundario:** Sistema Operativo, Procesos del Usuario

### **Precondiciones**
- El sistema de seguridad está instalado y activo
- Los servicios de monitoreo están habilitados
- Hay recursos de sistema disponibles (CPU, memoria)

### **Flujo Principal**
1. **Sistema** inicia el motor de escaneo en tiempo real
2. **Sistema** inicializa los detectores (Keylogger, Behavior, ML, Network)
3. **Sistema** registra hooks de monitoreo en el SO
4. **Sistema** comienza el monitoreo continuo de:
   - Procesos en ejecución
   - Acceso a archivos
   - Conexiones de red
   - Cambios en el registro
5. **Sistema** analiza cada evento contra las reglas de detección
6. **Sistema** calcula scores de riesgo para actividades sospechosas
7. **Sistema** mantiene estadísticas de rendimiento
8. **Sistema** actualiza la interfaz con información en tiempo real

### **Flujos Alternativos**
- **FA-01:** Si se detecta una amenaza → Ejecutar CU-10 (Respuesta a Incidentes)
- **FA-02:** Si recursos insuficientes → Reducir frecuencia de escaneo
- **FA-03:** Si error en detector → Continuar con detectores restantes

### **Postcondiciones**
- El sistema mantiene protección continua
- Los eventos se registran en logs
- La interfaz muestra el estado actual

### **Requisitos No Funcionales**
- **Rendimiento:** < 5% uso de CPU en promedio
- **Disponibilidad:** 99.9% uptime
- **Latencia:** Detección en < 2 segundos

---

## 🔑 CU-02: Detección de Keylogger

### **Descripción General**
El sistema identifica software malicioso que captura pulsaciones de teclado mediante análisis de comportamiento y patrones.

### **Actores**
- **Principal:** Detector de Keylogger
- **Secundario:** Sistema de Archivos, Registro de Windows

### **Precondiciones**
- El detector de keylogger está activo
- Las definiciones de amenazas están actualizadas
- El sistema tiene permisos de administrador

### **Flujo Principal**
1. **Detector** monitore procesos en busca de comportamientos sospechosos:
   - Hooks de teclado (SetWindowsHookEx)
   - Acceso a APIs de entrada (GetAsyncKeyState)
   - Creación de archivos de log sospechosos
   - Comunicación de red no autorizada
2. **Detector** analiza patrones de archivos:
   - Nombres sospechosos (keylog, passwords, etc.)
   - Ubicaciones inusuales
   - Atributos ocultos
3. **Detector** examina el comportamiento de procesos:
   - Consumo anómalo de recursos
   - Acceso a ventanas de otras aplicaciones
   - Persistencia en el sistema
4. **Detector** calcula score de riesgo combinado
5. **Detector** compara contra umbral de detección (configurable)
6. Si score > umbral → **Detector** genera alerta de keylogger

### **Flujos Alternativos**
- **FA-01:** Si proceso está en whitelist → Ignorar detección
- **FA-02:** Si score borderline → Marcar para monitoreo extendido
- **FA-03:** Si confirmación requerida → Solicitar acción del usuario

### **Postcondiciones**
- La amenaza se registra en el log
- Se notifica al usuario (si configurado)
- Se inicia respuesta automática (si habilitada)

---

## 🔒 CU-03: Cuarentena de Archivos

### **Descripción General**
El sistema aísla archivos sospechosos o maliciosos para prevenir daños mientras permite recuperación posterior.

### **Actores**
- **Principal:** Usuario o Sistema
- **Secundario:** Handler de Cuarentena, Sistema de Archivos

### **Precondiciones**
- Se ha detectado un archivo sospechoso
- Hay espacio disponible en la cuarentena
- El usuario tiene permisos suficientes

### **Flujo Principal**
1. **Actor** solicita cuarentena de archivo (manual o automática)
2. **Sistema** valida la ruta del archivo
3. **Sistema** verifica permisos de acceso
4. **Sistema** calcula hash del archivo original
5. **Sistema** crea directorio único en cuarentena
6. **Sistema** copia archivo a cuarentena (con compresión opcional)
7. **Sistema** genera metadatos de cuarentena:
   - Ruta original
   - Fecha/hora de cuarentena
   - Razón de cuarentena
   - Hash del archivo
   - Información del usuario
8. **Sistema** guarda metadatos en base de datos
9. **Sistema** elimina archivo original (opcional, configurable)
10. **Sistema** actualiza estadísticas de cuarentena

### **Flujos Alternativos**
- **FA-01:** Si archivo no existe → Mostrar error
- **FA-02:** Si archivo en uso → Programar cuarentena en próximo reinicio
- **FA-03:** Si cuarentena llena → Ofrecer limpiar archivos antiguos
- **FA-04:** Si error de permisos → Solicitar elevación de privilegios

### **Postcondiciones**
- Archivo aislado de forma segura
- Metadatos guardados para restauración
- Usuario notificado del resultado

---

## 🛡️ CU-04: Gestión de Amenazas

### **Descripción General**
El usuario visualiza, analiza y toma acciones sobre las amenazas detectadas por el sistema.

### **Actores**
- **Principal:** Usuario
- **Secundario:** Interface Gráfica, Motor Antivirus

### **Preconditions**
- Hay amenazas detectadas en el sistema
- La interfaz gráfica está activa
- El usuario tiene permisos apropiados

### **Flujo Principal**
1. **Usuario** accede al visor de amenazas
2. **Sistema** presenta lista de amenazas detectadas con:
   - Nombre del proceso/archivo
   - Nivel de riesgo (LOW, MEDIUM, HIGH, CRITICAL)
   - Score de detección
   - Timestamp de detección
   - Detalles técnicos
3. **Usuario** selecciona una amenaza específica
4. **Sistema** muestra árbol de decisión de análisis
5. **Usuario** elige acción a realizar:
   - Detener proceso
   - Poner en cuarentena
   - Agregar a whitelist
   - Localizar archivo
   - Ver detalles técnicos
6. **Sistema** ejecuta la acción seleccionada
7. **Sistema** proporciona feedback del resultado
8. **Sistema** actualiza la lista de amenazas

### **Flujos Alternativos**
- **FA-01:** Si no hay amenazas → Mostrar mensaje informativo
- **FA-02:** Si acción falla → Mostrar error y alternativas
- **FA-03:** Si múltiples amenazas → Permitir acciones en lote

### **Postcondiciones**
- Las acciones se registran en el log
- El estado de las amenazas se actualiza
- La interfaz refleja los cambios

---

## ⚙️ CU-05: Configuración del Sistema

### **Descripción General**
El administrador personaliza parámetros del sistema antivirus para optimizar rendimiento y detección.

### **Actores**
- **Principal:** Administrador
- **Secundario:** Sistema de Configuración

### **Precondiciones**
- El usuario tiene privilegios de administrador
- El sistema está en estado estable
- Los archivos de configuración son accesibles

### **Flujo Principal**
1. **Administrador** accede al panel de configuración
2. **Sistema** presenta categorías de configuración:
   - Protección en tiempo real
   - Umbrales de detección
   - Auto-cuarentena
   - Rendimiento del sistema
   - Logging y reportes
   - Actualizaciones
3. **Administrador** modifica parámetros deseados
4. **Sistema** valida la configuración:
   - Rangos de valores
   - Compatibilidad entre settings
   - Impacto en rendimiento
5. **Sistema** aplica configuración en tiempo real
6. **Sistema** guarda configuración persistente
7. **Sistema** notifica el éxito de la configuración

### **Flujos Alternativos**
- **FA-01:** Si configuración inválida → Mostrar errores y sugerencias
- **FA-02:** Si requiere reinicio → Notificar al usuario
- **FA-03:** Si configuración de fábrica → Solicitar confirmación

### **Postcondiciones**
- Nueva configuración está activa
- Cambios persisten entre reinicios
- Sistema funciona con nuevos parámetros

---

## 🧠 CU-06: Análisis de Comportamiento

### **Descripción General**
El sistema analiza patrones de comportamiento de procesos para detectar actividad maliciosa sin firmas específicas.

### **Actores**
- **Principal:** Detector de Comportamiento
- **Secundario:** Monitor de Performance, Sistema Operativo

### **Precondiciones**
- El análisis de comportamiento está habilitado
- Hay baseline establecido de comportamiento normal
- Los contadores de rendimiento están disponibles

### **Flujo Principal**
1. **Detector** recopila métricas de procesos en ejecución:
   - Uso de CPU y memoria
   - Acceso a archivos y red
   - Creación de procesos hijos
   - Modificaciones del registro
2. **Detector** compara contra patrones normales establecidos
3. **Detector** identifica desviaciones estadísticas significativas:
   - Incrementos súbitos de recursos
   - Patrones de acceso anómalos
   - Comportamientos no autorizados
4. **Detector** aplica algoritmos de machine learning
5. **Detector** calcula score de anomalía
6. **Detector** evalúa contra umbrales configurados
7. Si anomalía significativa → **Detector** genera alerta

### **Flujos Alternativos**
- **FA-01:** Si proceso conocido/confiable → Reducir sensibilidad
- **FA-02:** Si comportamiento temporal → Monitorear tendencias
- **FA-03:** Si falso positivo recurrente → Ajustar algoritmos

### **Postcondiciones**
- Comportamientos anómalos registrados
- Baseline actualizado con nueva información
- Métricas de performance actualizadas

---

## 📊 CU-07: Generación de Reportes

### **Descripción General**
El sistema genera informes detallados sobre actividad de seguridad, amenazas detectadas y rendimiento del sistema.

### **Actores**
- **Principal:** Usuario/Administrador
- **Secundario:** Motor de Reportes, Base de Datos de Logs

### **Precondiciones**
- Hay datos históricos disponibles
- El motor de reportes está activo
- El usuario tiene permisos de acceso

### **Flujo Principal**
1. **Usuario** solicita generar reporte especificando:
   - Período de tiempo
   - Tipo de reporte (amenazas, rendimiento, resumen)
   - Formato de salida (HTML, PDF, JSON)
2. **Sistema** consulta base de datos con filtros aplicados
3. **Sistema** procesa y agrega datos:
   - Estadísticas de amenazas por tipo
   - Tendencias temporales
   - Eficacia de detección
   - Impacto en rendimiento
4. **Sistema** genera visualizaciones (gráficos, tablas)
5. **Sistema** compila reporte en formato solicitado
6. **Sistema** presenta reporte al usuario
7. **Usuario** puede exportar o compartir reporte

### **Flujos Alternativos**
- **FA-01:** Si no hay datos → Mostrar reporte vacío con explicación
- **FA-02:** Si error en generación → Ofrecer formato alternativo
- **FA-03:** Si reporte muy grande → Ofrecer paginación o filtros

### **Postcondiciones**
- Reporte generado exitosamente
- Datos exportados en formato solicitado
- Actividad de generación registrada

---

## 🔄 CU-08: Actualización de Firmas

### **Descripción General**
El sistema mantiene actualizadas las definiciones de amenazas y modelos de detección automáticamente.

### **Actores**
- **Principal:** Sistema de Actualización
- **Secundario:** Servidor de Definiciones, Motor ML

### **Precondiciones**
- Hay conexión a internet disponible
- El servicio de actualización está habilitado
- Hay espacio de almacenamiento suficiente

### **Flujo Principal**
1. **Sistema** verifica horario de actualización automática
2. **Sistema** consulta servidor central por nuevas definiciones
3. **Sistema** compara versiones locales vs. remotas
4. **Sistema** descarga actualizaciones disponibles:
   - Firmas de malware
   - Modelos de ML
   - Reglas de comportamiento
   - Configuraciones de fábrica
5. **Sistema** valida integridad de descargas (checksums)
6. **Sistema** aplica actualizaciones de forma gradual
7. **Sistema** recarga detectores con nuevas definiciones
8. **Sistema** registra éxito de actualización

### **Flujos Alternativos**
- **FA-01:** Si no hay conexión → Programar intento posterior
- **FA-02:** Si descarga corrupta → Reintentar desde backup
- **FA-03:** Si actualización falla → Mantener versión anterior

### **Postcondiciones**
- Definiciones actualizadas están activas
- Versión local sincronizada con servidor
- Log de actualización generado

---

## 📝 CU-09: Whitelist/Blacklist

### **Descripción General**
El usuario gestiona listas de exclusión y inclusión forzada para personalizar el comportamiento de detección.

### **Actores**
- **Principal:** Usuario
- **Secundario:** Motor de Detección, Sistema de Archivos

### **Precondiciones**
- El usuario conoce el archivo/proceso a gestionar
- Hay acceso a las configuraciones del sistema
- Las listas son modificables

### **Flujo Principal**
1. **Usuario** accede al gestor de listas
2. **Sistema** presenta listas actuales:
   - Whitelist (procesos/archivos confiables)
   - Blacklist (elementos sempre sospechosos)
3. **Usuario** selecciona acción:
   - Agregar elemento a whitelist
   - Agregar elemento a blacklist
   - Remover elemento existente
   - Modificar criterios de coincidencia
4. **Sistema** valida el elemento especificado
5. **Sistema** actualiza la lista correspondiente
6. **Sistema** sincroniza cambios con detectores activos
7. **Sistema** confirma cambio exitoso

### **Flujos Alternativos**
- **FA-01:** Si elemento ya existe → Mostrar advertencia y opciones
- **FA-02:** Si formato inválido → Sugerir formato correcto
- **FA-03:** Si elemento crítico del sistema → Solicitar confirmación

### **Postcondiciones**
- Listas actualizadas y activas
- Comportamiento de detección modificado
- Cambios persistidos en configuración

---

## 🚨 CU-10: Respuesta a Incidentes

### **Descripción General**
El sistema ejecuta acciones automáticas predefinidas cuando se detecta una amenaza, basado en políticas de seguridad.

### **Actores**
- **Principal:** Sistema de Respuesta
- **Secundario:** Detectores, Handler de Cuarentena, Sistema de Notificaciones

### **Precondiciones**
- Se ha detectado una amenaza confirmada
- Las políticas de respuesta están configuradas
- El sistema tiene permisos necesarios

### **Flujo Principal**
1. **Detector** notifica amenaza al sistema de respuesta
2. **Sistema** evalúa severidad y tipo de amenaza
3. **Sistema** consulta política de respuesta aplicable
4. **Sistema** ejecuta acciones según configuración:
   - **Nivel LOW:** Solo registro y notificación
   - **Nivel MEDIUM:** Cuarentena opcional + alerta
   - **Nivel HIGH:** Cuarentena automática + detener proceso
   - **Nivel CRITICAL:** Cuarentena + bloqueo + alerta inmediata
5. **Sistema** ejecuta acciones en orden de prioridad
6. **Sistema** registra todas las acciones tomadas
7. **Sistema** notifica resultado al usuario
8. **Sistema** actualiza estadísticas de respuesta

### **Flujos Alternativos**
- **FA-01:** Si acción falla → Intentar acción alternativa
- **FA-02:** Si confirmación requerida → Pausar hasta respuesta del usuario
- **FA-03:** Si conflicto con whitelist → Aplicar política de excepción

### **Postcondiciones**
- Amenaza contenida según política
- Todas las acciones registradas
- Usuario informado del resultado
- Sistema en estado seguro

---

## 📋 Matriz de Trazabilidad

| Caso de Uso | Requisitos Funcionales | Componentes Involucrados |
|-------------|------------------------|--------------------------|
| CU-01 | RF-001, RF-002, RF-003 | Engine, Detectores, UI |
| CU-02 | RF-004, RF-005 | KeyloggerDetector, ML |
| CU-03 | RF-006, RF-007 | QuarantineHandler |
| CU-04 | RF-008, RF-009 | ThreatViewer, UI |
| CU-05 | RF-010, RF-011 | SettingsComponent |
| CU-06 | RF-012, RF-013 | BehaviorDetector |
| CU-07 | RF-014, RF-015 | ReportGenerator |
| CU-08 | RF-016, RF-017 | UpdateManager |
| CU-09 | RF-018, RF-019 | WhitelistManager |
| CU-10 | RF-020, RF-021 | ResponseEngine |

---

## 🎯 Métricas de Éxito

| Caso de Uso | Métrica | Objetivo |
|-------------|---------|----------|
| CU-01 | Uptime del sistema | > 99.5% |
| CU-02 | Tasa de detección | > 95% |
| CU-03 | Tiempo de cuarentena | < 5 segundos |
| CU-04 | Tiempo de respuesta UI | < 2 segundos |
| CU-05 | Aplicación de configs | < 1 segundo |
| CU-06 | Falsos positivos | < 5% |
| CU-07 | Tiempo generación | < 30 segundos |
| CU-08 | Frecuencia updates | Diaria |
| CU-09 | Aplicación reglas | Inmediata |
| CU-10 | Tiempo respuesta | < 3 segundos |