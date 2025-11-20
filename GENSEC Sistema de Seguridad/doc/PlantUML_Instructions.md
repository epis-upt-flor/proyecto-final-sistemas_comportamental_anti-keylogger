# 🎨 DIAGRAMAS PLANTUML - UNIFIED ANTIVIRUS

## 📋 Archivos Creados

He creado 4 diagramas PlantUML profesionales para tu presentación:

### 1. **`architecture.puml`** - Arquitectura Completa del Sistema
- **Uso**: Slide principal para mostrar la arquitectura completa
- **Contiene**: Todas las capas, componentes y conexiones
- **Ideal para**: Explicación técnica detallada

### 2. **`sequence_flow.puml`** - Diagrama de Secuencia
- **Uso**: Mostrar el flujo temporal de detección
- **Contiene**: Interacciones entre componentes paso a paso  
- **Ideal para**: Explicar cómo funciona en tiempo real

### 3. **`components.puml`** - Diagrama de Componentes Detallado
- **Uso**: Vista técnica de interfaces y dependencias
- **Contiene**: Patrones de diseño, interfaces, conexiones
- **Ideal para**: Audiencia técnica/desarrolladores

### 4. **`simple_flow.puml`** - Flujo Simplificado
- **Uso**: Explicación fácil para cualquier audiencia
- **Contiene**: Proceso de detección paso a paso
- **Ideal para**: Presentación general/no técnica

---

## 🚀 Cómo Generar los Diagramas

### **Opción 1: Online (Recomendado)**
1. Ve a [PlantUML Online Server](http://www.plantuml.com/plantuml/uml/)
2. Copia y pega el código de cualquier archivo `.puml`
3. Haz clic en "Submit" 
4. Descarga como PNG, SVG o PDF

### **Opción 2: VSCode Extension**
1. Instala la extensión "PlantUML" en VSCode
2. Abre cualquier archivo `.puml`
3. Presiona `Ctrl+Shift+P` → "PlantUML: Preview Current Diagram"
4. Exporta como imagen

### **Opción 3: Línea de Comandos**
```bash
# Instalar PlantUML (requiere Java)
java -jar plantuml.jar architecture.puml

# Generar PNG
java -jar plantuml.jar -tpng *.puml

# Generar SVG (mejor calidad)
java -jar plantuml.jar -tsvg *.puml
```

---

## 🎯 Cuál Usar en tu Presentación

### **Para el Video de 5 Minutos:**

#### **Minuto 0:45 - 1:15 (Arquitectura)**
- **Usar**: `architecture.puml` 
- **Sebastian dice**: *"Como pueden ver, nuestro sistema tiene una arquitectura modular..."*
- **Mostrar**: Diagrama completo con las 4 capas principales

#### **Minuto 1:15 - 2:00 (Detectores)**
- **Usar**: `simple_flow.puml` (solo la parte de detectores)
- **Anthony explica**: *"Tenemos 4 detectores especializados trabajando..."*
- **Resaltar**: Los 4 iconos de detectores con sus características

#### **Minuto 2:00 - 3:00 (Funcionamiento)**
- **Usar**: `sequence_flow.puml`
- **Sebastian muestra**: *"Veamos cómo trabajan en tiempo real..."*
- **Animación**: Flujo de datos entre componentes

#### **Minuto 3:00 - 4:30 (Demo)**
- **Usar**: La aplicación real corriendo
- **Referencia**: `simple_flow.puml` para explicar lo que está pasando

---

## 🎨 Personalización de Colores

Los diagramas usan el theme `aws-orange` con colores personalizados:

- 🔵 **Azul** (#1976D2): Componentes principales
- 🟠 **Naranja** (#F57C00): Detectores y plugins  
- 🟢 **Verde** (#4CAF50): Interfaces y conexiones
- 🔴 **Rosa** (#E91E63): Usuario y acciones

### **Para cambiar colores:**
```plantuml
!theme aws-orange
' Cambiar a otros themes:
' !theme plain, blueprint, aws-orange, carbon-gray
```

---

## 💡 Tips para la Presentación

### **🎭 Explicación con Analogías:**
- **Architecture.puml**: *"Es como una empresa con diferentes departamentos"*
- **Sequence_flow.puml**: *"Como una cadena de producción en tiempo real"*
- **Simple_flow.puml**: *"Como un sistema de seguridad en un banco"*

### **🎯 Puntos Clave a Resaltar:**
1. **4 Detectores** trabajando simultáneamente
2. **Análisis conjunto** para mejor precisión
3. **Usuario en control** de las decisiones finales
4. **Arquitectura modular** y extensible

### **📱 Para Diferentes Audiencias:**
- **Técnica**: Usar `components.puml` y `architecture.puml`
- **General**: Usar `simple_flow.puml` y demo en vivo
- **Ejecutiva**: Enfocarse en beneficios y resultados

---

## 🔄 Modificaciones Rápidas

Si necesitas cambiar algo:

### **Cambiar Colores:**
```plantuml
skinparam component {
    BackgroundColor #TU_COLOR
    BorderColor #TU_BORDE
}
```

### **Agregar Componentes:**
```plantuml
component "🆕 Nuevo Detector" as NewDetector
NewDetector --> DecisionEngine
```

### **Cambiar Iconos:**
```plantuml
component "🔥 Tu Icono" as Component
```

---

## 🚀 Resultado Final

Con estos 4 diagramas tendrás:

✅ **Presentación profesional** con diagramas técnicos precisos
✅ **Explicación visual clara** del funcionamiento
✅ **Flexibilidad** para diferentes audiencias  
✅ **Calidad de imagen alta** para video/impresión
✅ **Coherencia visual** en todos los diagramas

¡Perfecto para impresionar en tu presentación de 5 minutos! 🎯✨