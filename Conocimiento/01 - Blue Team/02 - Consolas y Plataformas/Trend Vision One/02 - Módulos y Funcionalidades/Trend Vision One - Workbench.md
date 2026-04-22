---
tipo: modulo
area: blue-team
vendor: Trend Micro
producto: Trend Vision One
tags:
  - area/blue-team
  - vendor/trend
  - platform/vision-one
  - type/modulo
  - topic/triage
relacionado:
  - "[[Trend Vision One]]"
  - "[[MITRE ATT&CK]]"
  - "[[Triage]]"
---
# Trend Vision One - Workbench

## DEF
Workbench es el espacio central de investigación en Trend Vision One.

## USE
Se utiliza para:
- revisar alertas,
- analizar contexto,
- documentar la investigación,
- generar informes de investigación,
- pivotar hacia artefactos y actividad relacionada.

## USE
Cuando un detection model encuentra una coincidencia, el resultado práctico es la generación de una alerta en Workbench para investigación posterior.

## USE
Workbench también ayuda a mapear actividad observada con ATT&CK y a organizar mejor el análisis del caso.

## DIFF
- **Search** sirve para buscar y hacer hunting.
- **Workbench** sirve para investigar y dejar trazabilidad.

## WARN
No asumir que todo hallazgo implica remediación automática inmediata.
Primero suele aterrizar como Workbench alert.

## REL
- [[Trend Vision One]]
- [[MITRE ATT&CK]]
- [[Triage]]
- [[Trend Vision One - Detection Models]]