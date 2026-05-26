## Bloque 1 — Conceptos base

### **1.** Explícame en 60 segundos qué es **Cortex XSIAM** y en qué se diferencia de **Cortex XDR** y **Cortex XSOAR**.
~~Cortex es la respuesta de seguridad de palo alto.  XSIAM trata todo lo relativo a datos y gestion, junto a XSOAR que es la herramienta encargada de orquestar las automatizaciones, respuestas y alertas. Cortex XDR es el edr extendido que se instala con los agentes en los endpoints.~~ 
~~Se puede tener todo en una unica plataforma como XSIAM? En mi anterior trabajo teniamos todo unificado.~~ (<font color="#ff0000">Nota 2/5</font>)

<mark style="background:#fff88f">Cortex XSIAM</mark> es la plataforma SOC integrada de Palo Alto Networks. <mark style="background:#fff88f">Unifica capacidades de SIEM, XDR/EDR, SOAR, [[Glosario#^e472ab|UEBA]] , Threat Intel Management y ASM </mark>para centralizar ingesta, detección, investigación, automatización y respuesta. 
 
Cortex XDR está más enfocado en detección y respuesta extendida, especialmente endpoint, red y telemetría asociada al agente.
 
Cortex XSOAR es la plataforma SOAR orientada a orquestación, automatización, playbooks, gestión de casos e integraciones.

La diferencia clave es que XSIAM busca ser la capa SOC unificada: ingesta + correlación + investigación + automatización + respuesta, mientras que XDR se centra más en detección/respuesta extendida y XSOAR en automatización/orquestación.


### **2.** Describe el flujo lógico:

```
Log / Telemetría → Dataset / Preset → Alerta → Incidente → Investigación → Playbook → Cierre
```

¿Qué ocurre en cada fase?
En la primera fase se recolecta el log y se ingesta un datalake donde segun las reglas configuradas se disparan las alertas. Una alerta, o un puñado de estas, pueden crear incidentes que deben ser analizadas. segun la configuracion que se tenga los playbooks pueden lanzarse automaticamente o manualmente para adelantar la investigacion, escritura o medidas automaticas de contención. El cierre se puede realizar manualmente o mediante playbooks finalizados.

### **3.** ¿Qué diferencia hay entre una **alerta** y un **incidente** en XSIAM?
una alerta no tiene porqué ser un incidente, pueden haber varias alertas que no generen directamente un incidente porque las reglas de correlacion no la clasifican como amenaza.
### **4.** ¿Qué significa investigar por **causalidad**? ¿Qué mirarías en un árbol de procesos?
Investigar por causalidad se refiere a la investigacion que se realiza cuando se enlazan multiples elementos sospechosos a raiz de un elemento padre. un proceso que crea persitencia, intenta realizar movimiento lateral y realiza peticiones dns extrañas.
**5.** ¿Qué es más útil para threat hunting: un IOC o una TTP? Dame un ejemplo aplicado a XSIAM.
Es más util un TTP, ya que los IOC son volatiles mientras que parchear/ajustar reglas referente a un ttp bloquea o nos da una mejor visibilidad ante las estrategias que realizan los cibercriminales. un ejemplo sería beaconing? al realizar multiples peticiones denegadas al dns alertar.
_____

## Bloque 2 — XQL

**6.** ¿Qué es XQL y para qué lo usas en una investigación real?

**7.** ¿Qué diferencia hay entre consultar un **dataset** y consultar un **preset**? La documentación de XSIAM explica que los datasets pueden contener eventos EDR y logs de terceros, y que los presets ayudan a trabajar con esquemas comunes o “stories”.

**8.** ¿Cuándo usarías `incidents` y cuándo `alerts`?

**9.** Escribe una query XQL simple para buscar alertas críticas o altas de las últimas 24 horas.

**10.** Escribe una query para agrupar alertas por:

```
severityalert_namesource
```

**11.** Si una query XQL tarda demasiado o devuelve demasiados eventos, ¿cómo la optimizas?

**12.** ¿Qué campos buscarías para investigar ejecución sospechosa de PowerShell?