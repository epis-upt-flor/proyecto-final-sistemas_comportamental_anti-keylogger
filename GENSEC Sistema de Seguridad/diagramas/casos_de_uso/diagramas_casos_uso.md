# Diagramas de Casos de Uso - Sistema de Seguridad

## 🎯 Diagrama General de Casos de Uso

```plantuml
@startuml caso_uso_general
!define ICONURL https://raw.githubusercontent.com/tupadr3/plantuml-icon-font-sprites/master
!includeurl ICONURL/common.puml
!includeurl ICONURL/font-awesome-5/shield_alt.puml
!includeurl ICONURL/font-awesome-5/user.puml
!includeurl ICONURL/font-awesome-5/cog.puml

title Diagrama General de Casos de Uso - Sistema de Seguridad

' Actores
:Usuario: as usuario
:Administrador: as admin
:Sistema: as sistema

' Casos de uso principales
rectangle "Sistema de Seguridad Profesional" {
    
    ' Protección Core
    (Escaneo en Tiempo Real) as scan
    (Detección de Keylogger) as keylogger
    (Análisis de Comportamiento) as behavior
    (Respuesta a Incidentes) as response
    
    ' Gestión de Amenazas
    (Cuarentena de Archivos) as quarantine
    (Gestión de Amenazas) as threats
    (Whitelist/Blacklist) as lists
    
    ' Administración
    (Configuración del Sistema) as config
    (Actualización de Firmas) as updates
    (Generación de Reportes) as reports
}

' Relaciones Usuario
usuario --> threats
usuario --> quarantine
usuario --> lists
usuario --> reports

' Relaciones Administrador
admin --> config
admin --> reports
admin --> lists

' Relaciones Sistema
sistema --> scan
sistema --> keylogger
sistema --> behavior
sistema --> response
sistema --> updates

' Inclusiones
scan .> keylogger : <<include>>
scan .> behavior : <<include>>
threats .> quarantine : <<include>>
response .> quarantine : <<include>>

' Extensiones
keylogger .> response : <<extend>>
behavior .> response : <<extend>>
scan .> reports : <<extend>>

@enduml
```

---

## 🔍 CU-01: Escaneo en Tiempo Real

```plantuml
@startuml cu01_escaneo_tiempo_real
title CU-01: Escaneo en Tiempo Real

actor "Sistema" as sistema
participant "Motor Antivirus" as engine
participant "Detector Keylogger" as keydet
participant "Detector Comportamiento" as behdet
participant "Detector ML" as mldet
participant "Monitor Sistema" as monitor
participant "Interface Usuario" as ui

sistema -> engine : iniciar_escaneo()
activate engine

engine -> keydet : inicializar()
engine -> behdet : inicializar()
engine -> mldet : inicializar()
engine -> monitor : iniciar_monitoreo()

loop Monitoreo Continuo
    monitor -> engine : evento_sistema(proceso, archivo, red)
    
    par Análisis Paralelo
        engine -> keydet : analizar_evento(evento)
        keydet -> engine : score_keylogger
    and
        engine -> behdet : analizar_comportamiento(evento)
        behdet -> engine : score_comportamiento
    and
        engine -> mldet : predecir_amenaza(evento)
        mldet -> engine : score_ml
    end
    
    engine -> engine : calcular_score_total()
    
    alt Score > Umbral
        engine -> ui : mostrar_alerta(amenaza)
        engine -> sistema : ejecutar_respuesta()
    else Score Normal
        engine -> ui : actualizar_estadisticas()
    end
end

deactivate engine
@enduml
```

---

## 🔑 CU-02: Detección de Keylogger

```plantuml
@startuml cu02_deteccion_keylogger
title CU-02: Detección de Keylogger (Caso de Uso)

actor "Sistema" as sistema
actor "Administrador" as admin

rectangle "Subsistema Detección Keylogger" {
  (Detectar Keyloggers) as detectar
  (Analizar APIs de Proceso) as analizar_apis
  (Verificar Hooks de Teclado) as hooks
  (Verificar APIs Sospechosas) as apis_sospechosas
  (Analizar Ejecutable) as analizar_ejecutable
  (Predicción ML) as pred_ml
  (Consultar Firmas) as firmas
  (Calcular Score Final) as score
  (Notificar Amenaza Detectada) as notificar
}

sistema --> detectar
detectar --> analizar_apis
detectar --> hooks
detectar --> apis_sospechosas
detectar --> analizar_ejecutable
detectar --> pred_ml
detectar --> firmas
detectar --> score
score --> notificar
notificar --> sistema
admin --> detectar : Configura parámetros

@enduml
```

---

## 🔒 CU-03: Cuarentena de Archivos

```plantuml
@startuml cu03_cuarentena_archivos
title CU-03: Cuarentena de Archivos (Caso de Uso)

actor "Usuario" as usuario
actor "Sistema" as sistema

rectangle "Subsistema Cuarentena" {
  (Solicitar Cuarentena de Archivo) as solicitar
  (Verificar Existencia de Archivo) as verificar
  (Calcular Hash) as hash
  (Comprimir Archivo) as comprimir
  (Mover a Cuarentena) as mover
  (Guardar Metadata) as metadata
  (Eliminar Archivo Original) as eliminar
  (Registrar Evento) as registrar
  (Notificar Éxito) as exito
}

usuario --> solicitar
sistema --> solicitar
solicitar --> verificar
verificar --> hash
hash --> comprimir
comprimir --> mover
mover --> metadata
metadata --> eliminar
eliminar --> registrar
registrar --> exito
exito --> usuario
exito --> sistema

@enduml
```

---

## 🛡️ CU-04: Gestión de Amenazas

```plantuml
@startuml cu04_gestion_amenazas
title CU-04: Gestión de Amenazas (Caso de Uso)

actor "Usuario" as usuario

rectangle "Gestión de Amenazas" {
  (Visualizar Amenazas Detectadas) as visualizar
  (Seleccionar Amenaza) as seleccionar
  (Ver Detalles de Amenaza) as detalles
  (Detener Proceso Sospechoso) as detener
  (Poner en Cuarentena) as poner_cuarentena
  (Agregar a Whitelist) as whitelist
  (Actualizar Estado de Amenaza) as actualizar
  (Confirmar Acción) as confirmar
}

usuario --> visualizar
visualizar --> seleccionar
seleccionar --> detalles
detalles --> detener
detalles --> poner_cuarentena
detalles --> whitelist
detener --> actualizar
poner_cuarentena --> actualizar
whitelist --> actualizar
actualizar --> confirmar
confirmar --> usuario

@enduml
```

---

## ⚙️ CU-05: Configuración del Sistema

```plantuml
@startuml cu05_configuracion_sistema
title CU-05: Configuración del Sistema (Caso de Uso)

actor "Administrador" as admin

rectangle "Configuración del Sistema" {
    (Acceder a Configuración) as acceder
    (Modificar Parámetros) as modificar
    (Validar Configuración) as validar
    (Aplicar Configuración) as aplicar
    (Guardar Configuración) as guardar
    (Registrar Cambio) as registrar
    (Mostrar Errores) as errores
}

admin --> acceder
acceder --> modificar
modificar --> validar
validar --> aplicar
aplicar --> guardar
guardar --> registrar
validar --> errores
errores --> admin
registrar --> admin

@enduml
```

---

## 🧠 CU-06: Análisis de Comportamiento

```plantuml
@startuml cu06_analisis_comportamiento
title CU-06: Análisis de Comportamiento (Caso de Uso)

actor "Sistema" as sistema

rectangle "Análisis de Comportamiento" {
  (Iniciar Análisis de Comportamiento) as iniciar
  (Recolectar Métricas) as recolectar
  (Obtener Baseline) as baseline
  (Detectar Anomalías) as anomalias
  (Predicción ML) as pred_ml
  (Combinar Scores) as combinar
  (Generar Alerta Crítica) as alerta_critica
  (Generar Alerta Sospecha) as alerta_sospecha
  (Actualizar Baseline) as actualizar_baseline
}

sistema --> iniciar
iniciar --> recolectar
recolectar --> baseline
baseline --> anomalias
anomalias --> pred_ml
pred_ml --> combinar
combinar --> alerta_critica
combinar --> alerta_sospecha
combinar --> actualizar_baseline
alerta_critica --> sistema
alerta_sospecha --> sistema
actualizar_baseline --> baseline

@enduml
```

---

## 📊 CU-07: Generación de Reportes

```plantuml
db -> generator : datos_brutos[]
generator -> db : registrar_generacion_reporte(usuario, timestamp)
@startuml cu07_generacion_reportes
title CU-07: Generación de Reportes (Caso de Uso)

actor "Usuario" as usuario

rectangle "Generación de Reportes" {
  (Solicitar Reporte) as solicitar
  (Validar Parámetros) as validar
  (Consultar Datos) as consultar
  (Procesar Datos) as procesar
  (Crear Visualizaciones) as visualizar
  (Exportar Reporte) as exportar
  (Entregar Reporte) as entregar
  (Registrar Generación) as registrar
}

usuario --> solicitar
solicitar --> validar
validar --> consultar
consultar --> procesar
procesar --> visualizar
visualizar --> exportar
exportar --> entregar
entregar --> usuario
entregar --> registrar

@enduml
```

---

## 🔄 CU-08: Actualización de Firmas

```plantuml
@startuml cu08_actualizacion_firmas
title CU-08: Actualización de Firmas (Caso de Uso)

actor "Sistema" as sistema

rectangle "Actualización de Firmas" {
  (Verificar Actualizaciones Automáticas) as verificar
  (Consultar Definiciones) as consultar
  (Comparar Versiones) as comparar
  (Descargar Definición) as descargar
  (Verificar Integridad) as integridad
  (Aplicar Definición) as aplicar
  (Notificar Actualización Completa) as notificar
  (Programar Próximo Intento) as programar
}

sistema --> verificar
verificar --> consultar
consultar --> comparar
comparar --> descargar
descargar --> integridad
integridad --> aplicar
aplicar --> notificar
verificar --> programar
notificar --> sistema
programar --> sistema

@enduml
```

---

## 📄 CU-09: Whitelist/Blacklist

```plantuml
@startuml cu09_whitelist_blacklist
title CU-09: Gestión de Whitelist/Blacklist (Caso de Uso)

actor "Usuario" as usuario

rectangle "Gestión de Listas" {
  (Acceder a Gestión de Listas) as acceder
  (Agregar Elemento) as agregar
  (Remover Elemento) as remover
  (Modificar Elemento) as modificar
  (Validar Elemento) as validar
  (Actualizar Lista) as actualizar
  (Recargar Listas) as recargar
  (Mostrar Éxito) as exito
  (Mostrar Errores) as errores
}

usuario --> acceder
acceder --> agregar
acceder --> remover
acceder --> modificar
agregar --> validar
remover --> actualizar
modificar --> validar
validar --> actualizar
actualizar --> recargar
recargar --> exito
exito --> usuario
validar --> errores
errores --> usuario

@enduml
```

---

## 🚨 CU-10: Respuesta a Incidentes

```plantuml
@startuml cu10_respuesta_incidentes
title CU-10: Respuesta a Incidentes (Caso de Uso)

actor "Detector" as detector

rectangle "Respuesta a Incidentes" {
  (Detectar Amenaza) as detectar
  (Obtener Política de Respuesta) as politica
  (Priorizar Acciones) as priorizar
  (Cuarentena Automática) as cuarentena
  (Detener Proceso) as detener
  (Bloquear Red) as bloquear
  (Notificar Usuario) as notificar
  (Notificar Administrador) as escalar
  (Registrar Acción) as registrar
  (Generar Resumen) as resumen
  (Confirmar Incidente Resuelto) as resuelto
  (Solicitar Intervención Manual) as intervencion
}

detector --> detectar
detectar --> politica
politica --> priorizar
priorizar --> cuarentena
priorizar --> detener
priorizar --> bloquear
priorizar --> notificar
priorizar --> escalar
cuarentena --> registrar
detener --> registrar
bloquear --> registrar
notificar --> registrar
escalar --> registrar
registrar --> resumen
resumen --> resuelto
resumen --> intervencion
resuelto --> detector
intervencion --> detector

@enduml
```

---

## 🔄 Diagrama de Interacciones entre Casos de Uso

```plantuml
@startuml interacciones_casos_uso
title Interacciones entre Casos de Uso

' Casos de uso
(Escaneo Tiempo Real) as scan
(Detección Keylogger) as keylogger
(Análisis Comportamiento) as behavior
(Respuesta Incidentes) as response
(Cuarentena Archivos) as quarantine
(Gestión Amenazas) as threats
(Configuración Sistema) as config
(Actualización Firmas) as updates
(Whitelist/Blacklist) as lists
(Generación Reportes) as reports

' Interacciones principales
scan --> keylogger : activa
scan --> behavior : activa
keylogger --> response : dispara
behavior --> response : dispara
response --> quarantine : ejecuta
response --> threats : notifica
threats --> quarantine : solicita
threats --> lists : modifica
config --> scan : configura
config --> keylogger : ajusta umbrales
config --> behavior : define parámetros
updates --> keylogger : actualiza firmas
updates --> behavior : actualiza modelos
lists --> keylogger : aplica exclusiones
lists --> behavior : aplica exclusiones
scan --> reports : genera datos
threats --> reports : aporta estadísticas
response --> reports : contribuye métricas

' Dependencias
scan ..> config : depende
keylogger ..> updates : depende
behavior ..> updates : depende
quarantine ..> config : depende
response ..> config : depende

@enduml
```

---

## 📈 Métricas y KPIs de Casos de Uso

```plantuml
@startuml metricas_casos_uso
!define RECTANGLE class

title Métricas de Rendimiento por Caso de Uso

RECTANGLE "CU-01: Escaneo Tiempo Real" {
  + Uptime: >99.5%
  + CPU Usage: <5%
  + Memory Usage: <200MB
  + Response Time: <2s
}

RECTANGLE "CU-02: Detección Keylogger" {
  + Detection Rate: >95%
  + False Positives: <5%
  + Analysis Time: <1s
  + Coverage: 25+ indicators
}

RECTANGLE "CU-03: Cuarentena" {
  + Quarantine Time: <5s
  + Storage Efficiency: 70%
  + Recovery Success: >99%
  + Integrity Check: SHA256
}

RECTANGLE "CU-04: Gestión Amenazas" {
  + UI Response: <2s
  + Action Success: >98%
  + User Satisfaction: >4.5/5
  + Workflow Time: <30s
}

RECTANGLE "CU-05: Configuración" {
  + Apply Time: <1s
  + Validation Accuracy: 100%
  + Rollback Success: >99%
  + User Errors: <2%
}

RECTANGLE "CU-06: Análisis Comportamiento" {
  + Anomaly Detection: >90%
  + False Positives: <10%
  + Processing Delay: <3s
  + Pattern Recognition: ML-based
}

RECTANGLE "CU-07: Reportes" {
  + Generation Time: <30s
  + Data Accuracy: >99%
  + Export Success: >98%
  + Format Support: 3 types
}

RECTANGLE "CU-08: Updates" {
  + Update Frequency: Daily
  + Download Success: >99%
  + Apply Time: <60s
  + Rollback Capability: Yes
}

RECTANGLE "CU-09: Lists Management" {
  + Rule Application: Immediate
  + Validation Accuracy: 100%
  + Performance Impact: <1%
  + User Flexibility: High
}

RECTANGLE "CU-10: Respuesta Incidentes" {
  + Response Time: <3s
  + Action Success: >95%
  + Escalation Rate: <5%
  + Recovery Time: <10s
}

@enduml
```