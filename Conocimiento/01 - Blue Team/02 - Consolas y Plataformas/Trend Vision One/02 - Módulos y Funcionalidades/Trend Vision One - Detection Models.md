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
  - "[[Correlación de eventos]]"
  - "[[MITRE ATT&CK]]"
---
## Definición

Los **Detection Models** son modelos de detección avanzados que analizan datos, comportamientos y eventos de múltiples fuentes para identificar posibles amenazas de forma contextual e inteligente.

## Uso principal

- Cuando se detecta una coincidencia o patrón sospechoso → se genera una **alerta en Workbench** para investigación.
- Aprovechan **correlación de eventos** + **contexto rico** procedente de múltiples fuentes (endpoint, email, network, cloud, etc.).
- Se actualizan frecuentemente para adaptarse a técnicas de ataque cambiantes (threat intelligence + MITRE ATT&CK).

## Diferencias clave

> [!IMPORTANT]  
> No son simplemente firmas estáticas (como IOCs clásicos).  
> Su valor real está en:  
> - Contexto multi-fuente  
> - Lógica compleja  
> - Evolución continua del modelo (AI/ML + actualizaciones de Trend)

> [!WARNING]  
> Una coincidencia en un Detection Model **no implica remediación automática** por defecto.  
> Siempre requiere revisión en Workbench.

## Comparación: Detection Model vs IOC vs Correlation Rule

| Aspecto                    | IOC                        | Correlation Rule (básica)                   | Detection Model (Vision One)                            |
| -------------------------- | -------------------------- | ------------------------------------------- | ------------------------------------------------------- |
| Tipo                       | Indicador estático         | Regla de correlación simple                 | Modelo avanzado con correlación + contexto + AI         |
| Ejemplo                    | Hash SHA-256, IP maliciosa | 5 logins fallidos + acceso archivo sensible | Descargas masivas anormales + contexto usuario/endpoint |
| Fidelidad / Ruido          | Baja-Media                 | Media                                       | Alta (menor ruido gracias a contexto)                   |
| Genera alerta en Workbench | Sí (si se usa en reglas)   | Sí                                          | Sí (alertas prioritarias)                               |
| Actualización              | Manual o threat intel      | Predefinidas + custom                       | Frecuente por Trend + customizables                     |
| Nivel de inteligencia      | Bajo                       | Medio                                       | Alto (correlación + ML + evolución)                     |
| ¿Es solo una firma?        | Sí                         | No                                          | No                                                      |
| ¿Usa IOCs internamente?    | —                          | A veces                                     | Sí, como parte de la lógica                             |

## Relaciones importantes

- [[Trend Vision One - Workbench]]
- [[Correlación de eventos]]
- [[MITRE ATT&CK]]
- [[Custom Detection Models]]
- [[Detection Model Management]] → sección donde se gestionan y crean modelos personalizados

## Resumen rápido

- **No es un IOC** → Los IOC son puntuales y estáticos.  
- **Es más que una correlation rule básica** → Incorpora correlación + contexto multi-fuente + inteligencia artificial + actualización continua.  
- **En una frase**: Un Detection Model es una **correlation rule evolucionada y potenciada por AI**, diseñada para generar alertas de alta fidelidad en entornos XDR.

> [!TIP]  
> Para crear uno custom:  
> Ve a → **Agentic SIEM & XDR** → **Detection Model Management**  
> Puedes definir filtros de eventos, umbrales, operadores lógicos, frecuencia, etc.
