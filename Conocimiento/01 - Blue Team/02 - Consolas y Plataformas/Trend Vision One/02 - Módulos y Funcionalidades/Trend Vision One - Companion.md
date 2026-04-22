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
relacionado:
  - "[[Trend Vision One - Workbench]]"
  - "[[Trend Vision One SecOps Advanced - MOC]]"
---
# Trend Vision One - Companion

> **Fecha de referencia**: Marzo 2026  

## Definición

**Trend Companion** (o **TrendAI Companion**) es un **asistente de ciberseguridad impulsado por IA generativa** integrado nativamente en **Trend Vision One**. Actúa como un advisor inteligente que ayuda a los analistas de seguridad (de todos los niveles) en la **investigación**, **análisis** y **respuesta** a incidentes y alertas de seguridad.

Está potenciado por **Trend Cybertron** (la IA avanzada de Trend Micro) y aprovecha décadas de innovación en machine learning + threat intelligence global.

## Uso principal

- Proporciona asistencia en tiempo real mediante interacción en **lenguaje natural** (chatbot dentro de la plataforma).
- Reduce la fatiga por alertas, el cambio de contexto y el tiempo de respuesta.
- Acelera flujos de trabajo diarios en el SOC (Security Operations Center).
- Soporta desde analistas junior hasta expertos senior.

### Funciones clave destacadas
- Genera y refina consultas de búsqueda (threat hunting) con prompts simples.
- Resume alertas, investigaciones y notas de casos.
- Decodifica y explica scripts complejos, comandos de línea (PowerShell, cmd, etc.), incluso si están ofuscados.
- Interpreta técnicas de ataque observadas (basado en MITRE ATT&CK).
- Sugiere pasos de respuesta y remediación guiada.
- Analiza eventos para detectar patrones recurrentes o anomalías.
- Proporciona orientación contextual en toda la plataforma (Workbench, Search, etc.).

> [!TIP]  
> Logra hasta **99% más rápido en tiempos de remediación** en algunos escenarios, pasando de reactivo a proactivo.

## Diferencias clave

> [!IMPORTANT]  
> No es un simple chatbot genérico (como ChatGPT).  
> Está **fine-tuned** con conocimiento específico de ciberseguridad de Trend Micro + threat intelligence de millones de sensores globales (500.000+ clientes).

> [!WARNING]  
> Las sugerencias de Companion son **asistivas**, no automáticas. Siempre valida y revisa antes de actuar (no reemplaza al analista humano).

## Comparación: Companion vs Otras herramientas de IA en XDR/SIEM

| Aspecto                     | Chatbot genérico (ej. ChatGPT) | Detection Models (Vision One) | Trend Companion (Vision One)                          |
|-----------------------------|--------------------------------|--------------------------------|-------------------------------------------------------|
| Integración                 | Externa (copiar-pegar)         | Nativa en plataforma           | Nativa y contextual en toda la UI                     |
| Conocimiento base           | General                        | Lógica de correlación + ML     | IA generativa + threat intel específica de Trend      |
| Interacción                 | Texto libre                    | Automática / predefinida       | Lenguaje natural + contextual (en alertas, workbench) |
| Funciones principales       | Respuestas generales           | Detección de patrones          | Investigación, resumen, decoding scripts, sugerencias |
| Fidelidad / Precisión       | Variable (alucinaciones)       | Alta en detección              | Alta en análisis contextual (menos ruido)             |
| Actualización               | Dependiente del proveedor      | Frecuente por Trend            | Evoluciona con Cybertron + threat intel continua      |
| ¿Genera alertas?            | No                             | Sí                             | No (asiste en alertas existentes)                     |
| Nivel de soporte SOC        | Bajo-Medio                     | Automatizado                   | Alto (amplifica analistas de todos niveles)           |

## Relaciones importantes

- [[Trend Vision One - Workbench]] → donde más se usa Companion para resumir y guiar investigaciones.
- [[Detection Models]] → Companion puede ayudar a entender o refinar resultados de estos modelos.
- [[Correlación de eventos]]
- [[MITRE ATT&CK]] → Companion explica técnicas observadas en este framework.
- [[Trend Cybertron]] → motor de IA que lo potencia.
- [[Agentic SIEM & XDR]] → sección donde interactúas con Companion.

## Resumen rápido

- **En una frase**: Trend Companion es tu **co-piloto IA** dentro de Vision One: acelera investigaciones, decodifica amenazas complejas y guía respuestas con contexto rico de threat intelligence, reduciendo tiempo y esfuerzo en el SOC.

> [!TIP]  
Úsalo como un **acelerador de análisis**:  
primero para entender la alerta,  
después para resumir contexto,  
y por último para ayudarte a redactar notas o pivotar con búsquedas
> Para usarlo: En la consola de Vision One, busca el ícono de Companion (chat) en Workbench, alertas o Search. Escribe en lenguaje natural, ej:  
> - "Summarize this alert and suggest next steps"  
> - "Explain this PowerShell script"  
> - "Generate a query for suspicious logins last 24h"

