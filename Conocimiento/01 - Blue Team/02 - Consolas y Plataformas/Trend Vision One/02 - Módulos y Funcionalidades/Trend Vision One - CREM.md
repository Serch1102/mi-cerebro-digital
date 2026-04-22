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
  - "[[Trend Vision One]]"
  - "[[Trend Vision One - Cyber Risk Overview]]"
  - "[[Trend Vision One - Companion]]"
  - "[[Cyber Risk Exposure Management]]"
  - "[[MITRE ATT&CK]]"
---

# Trend Vision One - CREM

**Cyber Risk Exposure Management** (CREM) es el módulo de gestión proactiva de exposición al riesgo cibernético dentro de Trend Vision One.

## Definición

CREM (anteriormente conocido como Attack Surface Risk Management) es una solución impulsada por IA que proporciona visibilidad continua del **attack surface** completo (conocido, desconocido, oculto y de terceros), evalúa riesgos en tiempo real, prioriza según impacto al negocio y automatiza acciones de mitigación.

Integra capacidades como EASM, CAASM, Vulnerability Risk Management, Security Posture Management, gestión de identidades, cloud, APIs, shadow AI y cumplimiento normativo en una única vista.

## Uso principal

- Descubrimiento continuo y clasificación de activos (on-prem, cloud, hybrid, SaaS, IoT/OT).
- Evaluación en tiempo real de riesgos contextualizados (vulnerabilidades, misconfiguraciones, exposición externa).
- Cálculo de **puntuación de riesgo organizacional** (basada en modelos NIST SP 800-30/800-60 + inteligencia de negocio).
- Priorización accionable: recomendaciones específicas y orquestación de remediación.
- Dashboards y reporting para comunicar riesgo cibernético en términos empresariales.
- Soporte multi-tenant (visión agregada para MSPs o entornos grandes).

## Diferencias clave

> [!IMPORTANT]  
> CREM no es solo un escáner de vulnerabilidades ni un EASM tradicional.  
> Su fortaleza está en la **unificación** de múltiples disciplinas de riesgo en un solo motor de IA, con scoring contextual que mapea exposición a impacto negocio (no solo CVSS).

> [!WARNING]  
> Requiere activación explícita en la consola (menú lateral → Cyber Risk Exposure Management → Cyber Risk Overview).  
> Existen paquetes diferenciados (Core, Essentials, etc.) con capacidades variables — verifica tu licencia para evitar expectativas erróneas en examen.

## Comparación: CREM vs Otras aproximaciones de gestión de riesgo

| Aspecto                     | Escáner tradicional de vulnerabilidades | EASM standalone | CREM en Trend Vision One                  |
|-----------------------------|-----------------------------------------|-----------------|--------------------------------------------|
| Alcance                     | Solo assets conocidos + vulns           | Exposición externa | Attack surface completo + contextual       |
| Evaluación                  | CVSS / severidad estática               | Exposición internet-facing | Scoring dinámico + impacto negocio + IA    |
| Priorización                | Por severidad técnica                   | Por accesibilidad externa | Por riesgo real (probabilidad + impacto)   |
| Automatización remediación  | Limitada                                | Baja            | Alta (recomendaciones + orquestación)      |
| Integración con XDR/SIEM    | Baja                                    | Media           | Nativa (Workbench, Detection Models, etc.) |
| Enfoque                     | Reactivo                                | Parcialmente proactivo | Totalmente proactivo + predictivo          |

## Relaciones importantes

- [[Trend Vision One - Cyber Risk Overview]] → dashboard principal de CREM
- [[Trend Vision One - Workbench]] → correlación de riesgos con alertas de detección
- [[Trend Vision One - Companion]] → usa Companion para resumir riesgos o generar queries sobre exposición
- [[Trend Vision One]] → plataforma base
- [[MITRE ATT&CK]] → CREM mapea exposiciones a técnicas/ataques
- [[Correlación de eventos]] → alimenta el contexto de riesgo
- [[01 - Fundamentos internos]] → conceptos transversales como asset discovery y risk scoring

## Resumen rápido

- **No es un IOC ni una rule de detección** → Es un módulo de **gestión proactiva de exposición al riesgo** (previene antes de que ocurra la detección).
- **En una frase** → CREM transforma la visibilidad de attack surface en decisiones accionables, priorizando lo que realmente impacta al negocio y acelerando la reducción de riesgo cibernético.
- Ideal para: certificación SecOps Advanced (dominio de risk management), SOC proactivo y alineación con CISO/negocio.

> [!TIP]  
> En la consola: ve a **Cyber Risk Exposure Management → Cyber Risk Overview** para ver el **Risk Score** global.  
> Usa filtros por asset type (cloud, identity, external) y explora **Risk Events** para priorizar remediaciones.  
> Pregunta típica de examen: "¿Qué módulo unifica EASM, CAASM y VRM en Vision One?" → Respuesta: CREM.
