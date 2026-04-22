---
Transferencia de archivos:
Reverse shell:
Pivoting:
---

## Chisel

 **Explicación y Funcionalidades:**
Chisel es una herramienta de código abierto que ==permite crear túneles de red seguros y facilita el acceso remoto a sistemas en entornos controlados y no controlados.== Utiliza técnicas de criptografía para asegurar la comunicación entre el cliente y el servidor, lo que garantiza la confidencialidad e integridad de los datos transmitidos a través del túnel. Chisel es altamente configurable y puede adaptarse a una variedad de escenarios de red.

**Papel en la Ciberseguridad:**
Chisel desempeña un papel crucial en la ciberseguridad al proporcionar una forma segura de establecer conexiones remotas a sistemas que pueden estar detrás de firewalls, NATs o restricciones de red. Facilita la administración remota de sistemas y el intercambio seguro de información entre diferentes dispositivos, lo que ayuda a los profesionales de la seguridad a realizar tareas de mantenimiento, diagnóstico y respuesta a incidentes de manera efectiva.



## Utilidad en Pivoting:
Chisel es especialmente útil en técnicas de pivoting, donde ==un atacante utiliza un sistema comprometido como punto de entrada para acceder a otros sistemas dentro de la red objetivo==. Al establecer túneles seguros a través de sistemas comprometidos, Chisel permite a los atacantes sortear las restricciones de red y amp==liar su alcance dentro de la infraestructura objetivo de manera encubierta==.



## Cheatsheet de Chisel:

Aquí tienes una cheatsheet con los comandos más comunes para usar Chisel y su explicación:

### Iniciar el servidor Chisel en el sistema destino:
   ``` bash
chisel server --reverse --port <puerto>
   ```
   - `--reverse`: Establece una conexión inversa desde el cliente.
   - `--port <puerto>`: Especifica el puerto en el que el servidor Chisel escuchará las conexiones entrantes.

### Iniciar el cliente Chisel en el sistema atacante y establecer un túnel:
   ``` bash
chisel client <servidor>:<puerto> R:<puerto_local>:<destino>:<puerto_destino>
   ```
   - `<servidor>:<puerto>`: Especifica la dirección y el puerto del servidor Chisel.
   - `R:<puerto_local>:<destino>:<puerto_destino>`: Define la configuración del túnel.



## Alternativas a Chisel:

- Ngrok
- Meterpreter
- SSH Tunneling
- **Proxychains:** Proporciona capacidades de pivoting utilizando proxies.

Estas alternativas también pueden utilizarse para establecer conexiones seguras y crear túneles de red, cada una con sus propias características y funcionalidades específicas.



## Ejemplos de Uso de Pivoting:

1. Establecer un túnel Chisel desde un sistema comprometido en la red interna a un servidor externo para exfiltrar datos.
2. Utilizar Chisel para establecer un túnel desde un sistema interno a través de un firewall y acceder a recursos en una red segmentada.
3. Emplear Chisel para establecer una conexión inversa desde un sistema comprometido a través de una cadena de sistemas pivotantes y comprometer sistemas internos en una red objetivo.