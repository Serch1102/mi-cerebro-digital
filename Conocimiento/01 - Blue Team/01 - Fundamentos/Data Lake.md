---
title: Data Lake
aliases:
  - Lago de datos
  - Security Data Lake
tags:
  - blue-team
  - fundamentos
  - data
  - siem
  - soc
  - telemetria
type: fundamento
categoria: Fundamentos
area: Blue Team
estado: activo
relacionado:
  - "[[Correlación de eventos]]"
  - "[[MITRE ATT&CK]]"
  - "[[TTPs]]"
---
## Definición

Un **Data Lake** es un repositorio diseñado para **almacenar grandes volúmenes de datos en bruto o semiestructurados**, procedentes de múltiples fuentes, sin exigir que todos tengan el mismo formato desde el principio.

En contexto **Blue Team / SOC**, un Data Lake sirve para **centralizar telemetría de seguridad y operación** como logs, eventos, alertas, artefactos de endpoint, actividad de red, identidad, correo, cloud y datos enriquecidos, permitiendo su posterior consulta, análisis y correlación.

A diferencia de una base de datos tradicional muy estructurada, el Data Lake está pensado para **ingestar primero y modelar después**, lo que da flexibilidad para investigación, hunting, analítica avanzada y explotación futura.

## Uso principal

- Centralizar datos de seguridad procedentes de múltiples herramientas y tecnologías.
- Conservar telemetría en volumen para búsquedas históricas, investigaciones y threat hunting.
- Servir como base para reglas de correlación, analítica avanzada y modelos de detección.
- Permitir que distintas capas de la plataforma consuman el mismo conjunto de datos.
- Facilitar enriquecimiento, normalización y reutilización de información operativa.
- Reducir silos entre endpoint, red, identidad, correo, cloud y otras fuentes.
- Soportar reporting, cuadros de mando, auditoría y análisis retrospectivo.

## Qué suele almacenar

Un Data Lake de seguridad puede contener, entre otros:

- Logs de autenticación.
- Eventos de proceso y actividad de endpoint.
- Telemetría de red.
- DNS, proxy y firewall.
- Eventos de correo y colaboración.
- Alertas de EDR, XDR, SIEM, IDS/IPS o CASB.
- Datos cloud de SaaS, IaaS y control plane.
- IoCs, enriquecimientos y contexto adicional.
- Resultados de analítica o scoring de riesgo.

## Cómo debe entenderse en un SOC

En un SOC, el Data Lake no suele ser “la parte bonita” que ve primero el analista, pero sí una de las piezas más importantes del backend.

Es, en la práctica, la **capa donde vive la materia prima** que luego usan:

- los motores de correlación,
- las reglas de detección,
- los módulos de hunting,
- los dashboards,
- las investigaciones históricas,
- y parte de la analítica avanzada de la plataforma.

Dicho de forma simple:

> [!IMPORTANT]
> El **Data Lake no es la alerta**.  
> El Data Lake es el **repositorio de datos** del que pueden salir alertas, correlaciones, búsquedas, contexto y analítica.

## Flujo lógico simplificado

1. Varias fuentes generan telemetría.
2. La plataforma la ingesta y la almacena en el Data Lake.
3. Parte de esos datos se normalizan, enriquecen o indexan.
4. Encima de esa base actúan búsquedas, correlaciones, modelos de detección y cuadros de mando.
5. El analista consume el resultado desde módulos como investigación, hunting, dashboards o incidentes.

## Diferencias clave

> [!IMPORTANT]
> Un Data Lake está orientado a **almacenar y explotar datos a escala**, no a presentar por sí mismo la experiencia completa de investigación al analista.

> [!WARNING]
> Error típico: confundir **Data Lake** con **SIEM**.  
> El SIEM suele usar un repositorio de datos por debajo, pero además añade lógica de detección, reglas, cuadros de mando, casos de uso y operación SOC.  
> El Data Lake es más bien la **capa de datos**, no necesariamente la plataforma operativa completa.

> [!WARNING]
> Otro error habitual: pensar que “Data Lake” significa “datos desordenados sin control”.  
> Aunque puede almacenar datos crudos, un buen Data Lake de seguridad necesita **gobierno, normalización, retención, control de acceso y estrategia de explotación**.

## Comparación: Data Lake vs SIEM vs Data Warehouse

| Aspecto | Data Lake | SIEM | Data Warehouse |
|--------|---|---|---|
| Función principal | Almacenar grandes volúmenes de datos variados | Detectar, correlacionar y operar seguridad | Analizar datos estructurados para negocio o reporting |
| Tipo de datos | Crudos, semiestructurados y variados | Datos de seguridad ya ingeridos y explotables | Datos estructurados y modelados |
| Flexibilidad | Alta | Media-alta | Media |
| Orientación | Base de datos/telemetría | Operación SOC | Analítica estructurada |
| Casos típicos | Hunting, histórico, analítica, backend | Alertas, correlación, incidentes, monitorización | BI, reporting ejecutivo, métricas estables |
| Requiere normalización previa estricta | No siempre | Normalmente sí, al menos parcial | Sí, habitualmente |
| Pensado para investigación operativa directa | No por sí solo | Sí | No |

## Relación con correlación y detección

Un Data Lake aporta mucho valor cuando se usa como base para:

- **Correlación de eventos** entre distintas fuentes.
- Reglas de detección que cruzan identidad, endpoint, red y cloud.
- Búsquedas históricas para validar si un comportamiento es nuevo o recurrente.
- Modelos analíticos que detectan anomalías, patrones o secuencias sospechosas.
- Enriquecimientos que contextualizan una alerta antes de llegar al analista.

Ejemplo mental útil:

- El **evento aislado** puede no decir gran cosa.
- El **conjunto de eventos en el Data Lake**, correlacionados y enriquecidos, puede revelar una intrusión real.

## Relación con el hunting

El Data Lake es una pieza central para actividades de **threat hunting** porque permite:

- Consultar grandes periodos de tiempo.
- Buscar patrones que no generaron alerta automática.
- Pivotar entre entidades: host, usuario, IP, hash, proceso, dominio, alerta.
- Construir hipótesis y validarlas con telemetría histórica.

Sin Data Lake, el hunting queda muy limitado porque el analista depende solo de alertas ya generadas o de logs dispersos.

## Ventajas operativas

- Escalabilidad para almacenar mucha telemetría.
- Flexibilidad para incorporar nuevas fuentes de datos.
- Base común para múltiples funciones de seguridad.
- Mejor capacidad de análisis histórico y retrospectivo.
- Reducción de silos entre herramientas.
- Reutilización de datos para distintos casos de uso.
- Soporte para hunting, investigación y analítica avanzada.

## Limitaciones y retos

- Si se ingesta demasiado sin estrategia, se convierte en ruido caro.
- La calidad del dato condiciona la calidad del análisis.
- Requiere gobierno de datos: retención, acceso, clasificación y normalización.
- Puede aumentar costes de almacenamiento e indexación.
- No aporta valor por sí solo si no hay casos de uso construidos encima.
- Puede generar una falsa sensación de visibilidad total aunque haya fuentes mal integradas.

## Trampas típicas de estudio o certificación

- Pensar que el Data Lake es una interfaz de investigación. No lo es por sí mismo.
- Confundirlo con el SIEM completo.
- Creer que solo almacena logs “bonitos” y estructurados.
- Asumir que todos los datos del Data Lake están listos para consumir sin normalización.
- Olvidar que su valor real aparece cuando se combina con correlación, búsqueda, detección y contexto.

## Relaciones importantes

- [[Correlación de eventos]]
- [[MITRE ATT&CK]]
- [[TTPs]]
- [[IOC vs IOA vs BIOC]]
- [[Microsoft Sentinel]]
- [[Cortex XSIAM]]
- [[00 - Trend Vision One]]

## Resumen rápido

- Un **Data Lake** es un repositorio escalable de datos variados.
- En Blue Team se usa para centralizar **telemetría de seguridad**.
- No es lo mismo que un SIEM, aunque un SIEM puede apoyarse en él.
- Su valor está en permitir **búsqueda, correlación, detección, hunting e investigación histórica**.
- Es una **capa de datos**, no necesariamente una experiencia operativa completa.
- Cuanto mejor sea la calidad, normalización y explotación del dato, mayor será su valor para el SOC.

> [!TIP]
> Fórmula rápida para memorizarlo:  
> **Data Lake = donde vive el dato**  
> **SIEM = donde se explota operativamente parte de ese dato**  
> **Detección = lo que se construye encima del dato**