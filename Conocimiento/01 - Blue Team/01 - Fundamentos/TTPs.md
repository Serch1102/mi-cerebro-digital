---
tipo: concepto
area: blue-team
tags:
  - area/blue-team
  - type/concepto
  - topic/ttp
  - topic/mitre
relacionado:
  - "[[MITRE ATT&CK]]"
  - "[[Trend Vision One - Workbench]]"
  - "[[Correlación de eventos]]"
---
## DEF
TTPs significa **Tactics, Techniques and Procedures**.

## DEF
- **Tactics**: objetivo general del atacante.
- **Techniques**: método general usado para alcanzar ese objetivo.
- **Procedures**: implementación concreta de una técnica.

## DIFF
- **Tactic** = el para qué.
- **Technique** = el cómo general.
- **Procedure** = el cómo exacto en la práctica.

## EX
Ejemplo:
- Tactic: Persistence
- Technique: Scheduled Task
- Procedure: creación concreta de una tarea programada con un comando específico

## USE
Este modelo ayuda a describir actividad ofensiva con un lenguaje estructurado y consistente.

## USE
En Blue Team sirve para:
- clasificar actividad observada,
- mapear comportamientos detectados,
- entender mejor el contexto del atacante.

## WARN
No confundir **Technique** con **Procedure**.
La técnica es una categoría más amplia; el procedimiento es un caso concreto de aplicación.

## REL
Ver también:
- [[MITRE ATT&CK]]
- [[Trend Vision One - Workbench]]
- [[Trend Vision One - Detection Models]]