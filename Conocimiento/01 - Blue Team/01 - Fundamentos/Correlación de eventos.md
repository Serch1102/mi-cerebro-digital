---
tipo: concepto
area: blue-team
tags:
  - area/blue-team
  - type/concepto
  - topic/correlacion
relacionado:
  - "[[Data Lake]]"
  - "[[Trend Vision One]]"
  - "[[Trend Vision One - Detection Models]]"
---
# Correlación de eventos

## DEF
La correlación de eventos consiste en relacionar eventos de seguridad aparentemente aislados para identificar patrones, contexto y posibles incidentes.

## USE
Su beneficio principal es descubrir relaciones ocultas entre eventos que por separado podrían parecer legítimos o poco relevantes.

## EX
Ejemplo:
- login anómalo,
- ejecución sospechosa,
- conexión externa inusual.

Por separado pueden pasar desapercibidos.
Correlados, pueden indicar compromiso.

## USE
La correlación mejora:
- visibilidad,
- priorización,
- calidad del triage,
- detección de amenazas complejas.

## WARN
Correlación no es simplemente “juntar logs”.
Implica contexto, relación temporal, lógica y relevancia.

## REL
- [[Data Lake]]
- [[Trend Vision One]]
- [[Trend Vision One - Detection Models]]