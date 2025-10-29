# FORMATO N° 7 - IMPLEMENTACIÓN DE METODOLOGÍAS ÁGILES

## UNIVERSIDAD PRIVADA DE TACNA
### FACULTAD DE INGENIERÍA
### ESCUELA PROFESIONAL DE INGENIERÍA DE SISTEMAS

---

**Curso:** Construcción de Software I  
**Docente:** ING. ALBERTO JONATAN FLOR RODRIGUEZ  
**Proyecto:** Sistema web con integración de Machine Learning para la detección anticipada de keyloggers en instituciones educativas - 2025  
**Integrantes:**
- Arce Bracamonte, Sebastian Rodrigo (2019092986)
- Chata Choque, Brant Antony (2020067577)

**Fecha:** Octubre 2025

---

## 1. METODOLOGÍA ÁGIL SELECCIONADA: SCRUM

### 1.1 Justificación de la Metodología
Para el desarrollo del sistema de detección de keyloggers, se ha seleccionado **SCRUM** como metodología ágil debido a:

- **Complejidad del proyecto:** Integración de ML, desarrollo web y ciberseguridad
- **Flexibilidad requerida:** Adaptación a nuevos requerimientos de seguridad
- **Colaboración intensiva:** Coordinación entre desarrollo, testing y documentación
- **Entregas incrementales:** Validación continua de componentes críticos de seguridad

### 1.2 Principios del Manifiesto Ágil Aplicados
1. **Individuos e interacciones** sobre procesos y herramientas
2. **Software funcionando** sobre documentación extensiva
3. **Colaboración con el cliente** sobre negociación contractual
4. **Respuesta ante el cambio** sobre seguir un plan

## 2. ESTRUCTURA DEL EQUIPO SCRUM

### 2.1 Roles Definidos

| Rol | Responsable | Responsabilidades |
|-----|-------------|-------------------|
| **Product Owner** | Sebastian Arce | - Definir y priorizar Product Backlog<br>- Validar criterios de aceptación<br>- Comunicación con stakeholders<br>- Toma de decisiones sobre funcionalidades |
| **Scrum Master** | Brant Chata | - Facilitar ceremonias Scrum<br>- Eliminar impedimentos<br>- Coaching del equipo<br>- Garantizar cumplimiento de Scrum |
| **Development Team** | Sebastian & Brant | - Desarrollo de código<br>- Testing y validación<br>- Documentación técnica<br>- Estimación de tareas |

### 2.2 Stakeholders
- **Docente:** ING. ALBERTO JONATAN FLOR RODRIGUEZ
- **Usuarios finales:** Administradores de TI en instituciones educativas
- **Expertos en dominio:** Especialistas en ciberseguridad

## 3. ARTEFACTOS SCRUM

### 3.1 Product Backlog
El Product Backlog está organizado por épicas y historias de usuario:

#### **ÉPICA 1: CORE DEL SISTEMA**
- US001: Como administrador, quiero un núcleo de gestión de plugins para poder extender funcionalidades
- US002: Como usuario, quiero un sistema de eventos para recibir notificaciones en tiempo real
- US003: Como desarrollador, quiero interfaces bien definidas para integrar nuevos componentes

#### **ÉPICA 2: DETECCIÓN DE AMENAZAS**
- US004: Como administrador, quiero detectores ML para identificar keyloggers automáticamente
- US005: Como analista, quiero detectores de comportamiento para identificar patrones sospechosos
- US006: Como administrador, quiero detectores de red para monitorear tráfico malicioso

#### **ÉPICA 3: MONITOREO Y ALERTAS**
- US007: Como usuario, quiero monitoreo de archivos para detectar cambios sospechosos
- US008: Como administrador, quiero monitoreo de procesos para identificar actividad maliciosa
- US009: Como analista, quiero sistema de alertas para responder rápidamente a amenazas

#### **ÉPICA 4: INTERFAZ Y CONFIGURACIÓN**
- US010: Como administrador, quiero una interfaz web para gestionar el sistema
- US011: Como usuario, quiero configuración centralizada para personalizar parámetros
- US012: Como auditor, quiero reportes y métricas para evaluar la efectividad

### 3.2 Sprint Backlog - SPRINT 1 (Semana 1)
**Objetivo del Sprint:** Establecer la base arquitectónica del sistema y componentes core

| ID | Historia de Usuario | Tareas | Responsable | Estimación | Estado |
|----|-------------------|--------|-------------|------------|--------|
| US001 | Core de gestión de plugins | - ✅ Diseñar arquitectura de plugins<br>- ✅ Implementar plugin_manager.py<br>- ✅ Crear interfaces base | Sebastian | 8h | **DONE** |
| US002 | Sistema de eventos | - ✅ Implementar event_bus.py<br>- ✅ Definir tipos de eventos<br>- ⚠️ Testing de eventos | Brant | 6h | **IN PROGRESS** |
| US003 | Interfaces del sistema | - ✅ Crear interfaces.py<br>- ⚠️ Documentar APIs<br>- ⚠️ Validar contratos | Sebastian | 4h | **IN PROGRESS** |
| US007 | Monitor de archivos | - ✅ Implementar file_monitor plugin<br>- ⚠️ Testing básico<br>- ⚠️ Integración con core | Brant | 6h | **IN PROGRESS** |
| DOC001 | Documentación inicial | - ❌ README.md del proyecto<br>- ❌ Guía de instalación<br>- ❌ Arquitectura técnica | Ambos | 4h | **To Do** |

**Total estimado:** 28 horas  
**Duración Sprint:** 1 semana (40 horas laborables)

### 3.3 Incremento del Producto
Al finalizar el Sprint 1, se entregará:
- Core funcional del sistema con gestión de plugins
- Sistema de eventos básico implementado
- Monitor de archivos operativo
- Documentación técnica inicial
- Arquitectura base validada

## 4. CEREMONIAS SCRUM

### 4.1 Sprint Planning
- **Duración:** 2 horas
- **Frecuencia:** Inicio de cada sprint
- **Participantes:** Todo el equipo Scrum
- **Objetivo:** Planificar el trabajo del sprint

### 4.2 Daily Scrum
- **Duración:** 15 minutos
- **Frecuencia:** Diaria
- **Formato:** ¿Qué hice ayer? ¿Qué haré hoy? ¿Qué impedimentos tengo?

### 4.3 Sprint Review
- **Duración:** 1 hora
- **Frecuencia:** Final de cada sprint
- **Participantes:** Equipo + stakeholders
- **Objetivo:** Demostrar incremento y obtener feedback

### 4.4 Sprint Retrospective
- **Duración:** 45 minutos
- **Frecuencia:** Después del Sprint Review
- **Objetivo:** Mejorar el proceso del equipo

## 5. DEFINICIÓN DE "TERMINADO" (DoD)

Una historia de usuario se considera terminada cuando:
- [ ] Código desarrollado y revisado
- [ ] Pruebas unitarias implementadas y pasando
- [ ] Pruebas de integración exitosas
- [ ] Documentación técnica actualizada
- [ ] Código versionado en repositorio
- [ ] Validación de criterios de aceptación
- [ ] Review del Product Owner aprobado

## 6. GESTIÓN DE RIESGOS DEL SPRINT

### 6.1 Riesgos Identificados

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|-------------|---------|------------|
| Complejidad técnica ML | Alta | Alto | Prototipado temprano, consulta con expertos |
| Integración de componentes | Media | Alto | Desarrollo modular, testing continuo |
| Disponibilidad de tiempo | Media | Medio | Buffer de tiempo, priorización clara |
| Cambios en requerimientos | Baja | Medio | Comunicación frecuente con stakeholders |

### 6.2 Plan de Contingencia
- **Reuniones de escalación:** Cada 2 días si hay bloqueos críticos
- **Backup técnico:** Consulta con docente y recursos académicos
- **Replanificación:** Ajuste de alcance si es necesario

## 7. HERRAMIENTAS UTILIZADAS

### 7.1 Gestión de Proyecto
- **GitHub Projects:** Para tablero Kanban y seguimiento de issues
- **GitHub Issues:** Para historias de usuario y tareas
- **GitHub Milestones:** Para sprints y entregas

### 7.2 Desarrollo
- **GitHub:** Control de versiones y colaboración
- **VS Code:** IDE principal de desarrollo
- **Python:** Lenguaje principal del proyecto
- **ONNX:** Para modelos de Machine Learning

### 7.3 Comunicación
- **WhatsApp:** Comunicación diaria del equipo
- **Google Meet:** Ceremonias Scrum virtuales
- **Email:** Comunicación formal con stakeholders

## 8. MÉTRICAS Y SEGUIMIENTO

### 8.1 Métricas del Sprint
- **Velocity:** Puntos de historia completados por sprint
- **Burndown Chart:** Progreso diario del sprint
- **Lead Time:** Tiempo desde creación hasta completado de tarea
- **Defect Rate:** Errores encontrados por funcionalidad

### 8.2 KPIs del Proyecto
- **% Completado del Product Backlog**
- **Satisfacción del Product Owner**
- **Calidad del código (cobertura de pruebas)**
- **Cumplimiento de entregas**

## 9. CRONOGRAMA DE SPRINTS

| Sprint | Duración | Objetivo Principal | Entregables | Estado Actual |
|--------|----------|-------------------|-------------|---------------|
| **Sprint 1** | Semana 1 | Core y arquitectura base | Núcleo funcional, monitor básico | 🟡 **80% COMPLETADO** |
| **Sprint 2** | Semana 2 | Detectores ML y comportamiento | Módulos de detección operativos | 🟢 **COMPLETADO** |
| **Sprint 3** | Semana 3 | Interfaz web y configuración | Dashboard funcional | 🟢 **COMPLETADO** |
| **Sprint 4** | Semana 4 | Integración y testing | Sistema completo integrado | 🔵 **EN PROGRESO** |
| **Sprint 5** | Semana 5 | Documentación y entrega | Producto final documentado | ⚪ **PENDIENTE** |

## 10. CRITERIOS DE ACEPTACIÓN GENERALES

### 10.1 Funcionales
- Sistema debe detectar keyloggers con >90% de precisión
- Interfaz web debe ser responsive y intuitiva
- Configuración debe ser centralizada y flexible
- Alertas deben generarse en tiempo real (<2 segundos)

### 10.2 No Funcionales
- Código debe tener >80% de cobertura de pruebas
- Documentación debe estar completa y actualizada
- Sistema debe ser modular y extensible
- Cumplimiento con estándares de seguridad

## 11. SPRINT 2 BACKLOG - DETECTORES AVANZADOS
**Estado General: 🟢 COMPLETADO**

| User Story | Tarea | Responsable | Estimación | Estado Real | Evidencia |
|------------|-------|-------------|------------|-------------|-----------|
| **US004** - ML Detector | T014 - Implementar detector ML | Developer 1 | 8h | ✅ **DONE** | `plugins/detectors/ml_detector/` |
| | T015 - Entrenar modelo ONNX | ML Engineer | 12h | ✅ **DONE** | `models/keylogger_model_large_*.onnx` |
| | T016 - Feature extraction | Developer 1 | 6h | ✅ **DONE** | `feature_extractor.py` |
| **US005** - Behavior Analysis | T017 - Behavior engine | Developer 2 | 8h | ✅ **DONE** | `plugins/detectors/behavior_detector/` |
| | T018 - Rule engine | Developer 2 | 6h | ✅ **DONE** | `behavior_engine.py, rule_engine.py` |
| | T019 - Whitelist manager | Developer 2 | 4h | ✅ **DONE** | `whitelist_manager.py` |
| **US006** - Network Analysis | T020 - Network detector | Developer 3 | 10h | ✅ **DONE** | `plugins/detectors/network_detector/` |
| | T021 - IP analyzer | Developer 3 | 6h | ✅ **DONE** | `ip_analyzer.py, network_analyzer.py` |
| | T022 - Threat intelligence | Developer 3 | 8h | ✅ **DONE** | `threat_intelligence.py` |

### Sprint 2 - Logros Principales:
✅ **Detector ML**: Sistema de machine learning con modelos ONNX funcional (99.76% accuracy)  
✅ **Análisis Comportamental**: Engine de reglas y whitelist dinámico operativo  
✅ **Detección de Red**: Análisis de tráfico e inteligencia de amenazas implementado  
✅ **Integración**: Todos los detectores integrados al sistema de plugins principal

---

## 12. REFLEXIÓN Y MEJORA CONTINUA

### 12.1 Lecciones Aprendidas (Sprint 0)
- La planificación detallada es crucial para proyectos complejos
- La comunicación frecuente evita malentendidos
- La modularidad facilita el desarrollo paralelo

### 12.2 Acciones de Mejora
- Implementar daily standups virtuales
- Usar templates para historias de usuario
- Establecer definición clara de "terminado"

---

**Firma del Product Owner:** Sebastian Arce Bracamonte  
**Firma del Scrum Master:** Brant Antony Chata Choque  
**Fecha:** Octubre 2025

---

*Este documento será actualizado al final de cada sprint para reflejar lecciones aprendidas y mejoras identificadas.*