---
Escaneo: 
Enumeración:
---
### ESCANEOS BÁSICOS CON NMAP

Si queremos hacer un escaneo básico de una máquina podemos hacerlo de esta forma:
``` bash
 Nmap <Target>
```

### ESCANEAR 2 MÁQUINAS A LA VEZ
También podemos hacer un escaneo de dos máquinas a la vez con nmap:

```bash
nmap <Target1> <Target2>
```

### ESCANEAR TODO EL RANGO DE RED

Un escaneo completo de nuestra red privada detectará todos los equipos conectados:

```bash
nmap 192.168.1.0/24
```

El `/24` indica que se deben escanear las 256 direcciones IP posibles en la red `192.168.1.0`.

### DESCUIBRIR HOSTS CON NMAP
Para descubrir hosts con nmap lo haremos así:

```bash
nmap -sn 192.168.0.0/24
```

### ENUMERAR RANGO DE PUERTOS

 Enumerar todos los puertos de una máquina o sólo un rango de ellos.
```bash
nmap -p1-65535 <Target>
```
o simplemente -p- también estaríamos enumerando todo el rango de puertos
```bash
nmap -p- <Target>
```

También podemos enumerar los 500, 100 o el número que queramos del top de los puertos más comunes, por tanto lo haríamos de esta forma:

```bash
nmap --top-ports <Target>
```


### ESCANEOS DE NMAP POR UDP (Cuando por TCP no nos encuentra lo que queremos)

```bah
nmap -sU <target>
```

Por ejemplo, para un escaneo más agresivo que intenta buscar servicios y versiones, puedes agregar `-sU -sV`.


### [[PARÁMETROS DE NMAP]]

- #### **OPCIÓN -sP** (Sondeo de Ping): 
  Esto sirve para detectar equipos conectados a mi red utilizando un ping:
  
- #### **OPCIÓN -sn**:
  Este parámetro sirve para detectar equipos encendidos dentro de nuestra web, es algo similar al arp-scan:

- #### **OPCIÓN -sS** (TCP Syn): 
  Con esta opción podremos hacer un escaneo más [[sigiloso]] sin dejar rastro en la máquina objetivo:

- #### **OPCIÓN -T (Plantillas de temporizado)**:
  El parámetro `-T` de nmap sirve para aplicar una plantilla para hacer más rápidos o no los escaneos; y tenemos hasta 5 posibles plantillas, siendo la 5 la más rápida.

- #### **OPCIÓN -vvv (Triple verbose)**:
  Esto sirve para que a medida que encuentre algo, nos lo vaya reportando al mismo tiempo.

- #### **OPCIÓN -sS(SYN Stealth)**: 
  Indica que se realizará un escaneo de "SYN Stealth". Este tipo de escaneo es una técnica utilizada para enumerar puertos en un sistema objetivo sin establecer una conexión completa. En lugar de completar el proceso de tres vías (SYN, SYN-ACK, ACK) como lo hace un escaneo TCP convencional, el escaneo de "SYN Stealth" envía solo un paquete SYN al puerto objetivo.
  El proceso es el siguiente:
  
  1. Nmap envía un paquete SYN al puerto de destino.
 
  2. Si el puerto está abierto, el sistema objetivo responderá con un paquete SYN-ACK.

  3. Nmap responde al paquete SYN-ACK con un paquete RST (reset) para cerrar la conexión.

- #### **OPCIÓN -n**:
  Evita la resolución de DNS, lo que significa que Nmap no intentará resolver nombres de dominio para las direcciones IP especificadas.
  
- #### **OPCIÓN -Pn**: 
  Indica que no se realice detección de hosts, lo que reduce aún más el ruido generado por el escaneo. Esto puede ser útil cuando sospechas que los hosts están detrás de un firewall que bloquea las respuestas a los paquetes de sondeo.
  
- #### **OPCIÓN -D (decoy)**: 
  Esto sirve para confundir el firewall. Es decir, sirve para indicar otra dirección IP y hacerle creer al firewall que además de lanzar nosotros los paquetes, también lo haga otra dirección IP; y por eso en las instrucciones nos pone que esto sirve para disimular el análisis con señuelos.
  ##### ¡¡¡Es importante mencionar que el uso de decoys puede ser detectado por sistemas de detección de intrusiones más avanzados y no es una técnica garantizada para eludir la detección!!!
  
- #### **OPCIÓN --SOURCE PORT (Regular el origen de los paquetes)**: 
  Durante un escaneo Nmap, se utiliza un puerto de origen aleatorio para iniciar el escaneoy la respuesta vuelve a entrar por otro puerto aleatorio.
  
- #### **OPCIÓN --data-length (Modificar la longitud del paquete enviado)**:
  Es posible que un firewall cuente con restricciones dependiendo del tamaño de paquete. Por lo que podemos modificar este tamaño para engañar al firewall:![[Pasted image 20240218025926.png]]Este va a ser el tamaño mínimo que va a tener el paquete, pero le podemos sumar cantidades adicionales de tamaño para estos paquetes con el parámetro --data-length:![[Pasted image 20240218031042.png]]Y en wireshark si analizamos este fichero .cap vemos que el tamaño de los paquetes es mayor en un 20:![[Pasted image 20240218031120.png]]
  
- #### **OPCIÓN --spoof-mac**:
  Falsificar la dirección MAC. Esta opción permite especificar una dirección MAC, prefijo o nombre de fabricante para falsificar la dirección MAC durante un escaneo. Esto puede ser útil para eludir la detección basada en la dirección MAC real del dispositivo emisor de los paquetes. Por ejemplo:
  ```bash
  nmap --spoof-mac <dirección_mac/prefijo/nombre_fabricante> <objetivo>
  ```

- #### **OPCIÓN --badsum**:
  Enviar paquetes con una suma de comprobación TCP/UDP falsa. Esta opción permite enviar paquetes con una suma de comprobación TCP/UDP falsa. La suma de comprobación se utiliza para verificar la integridad de los datos en los paquetes de red. Al enviar paquetes con una suma de comprobación falsa, se puede intentar evadir la detección de intrusiones y otros mecanismos de seguridad que verifican la integridad de los paquetes. Es importante tener en cuenta que el uso de esta opción puede ser detectado por sistemas de seguridad y está sujeto a las políticas de seguridad de la red.
  
- #### **OPCIÓN --script-mtu**: 
  El parámetro mtu sirve para **ajustar el tamaño máximo de paquete** sin fragmentar (mtu) para los paquetes enviados durante las pruebas de detección de firewall. De esta forma podemos **evadir firewalls que tengan algún tipo de tope para la detección de este tipo de paquetes**. Es importante recalcar que se debe poner siempre un número que sea múltiplo de 8, por ejemplo el 8, 16, etc...


### SCRIPTS DE NMAP

- #### **Script Default**:
  Con el script **Default** ejecutamos los **scripts** de nmap **por defecto para obtener información de las máquinas objetivo**:

  ```bash
  nmap --script default <Target>
  ```

- #### **Script Vuln**:
  Con el script **vuln** podemos brindar **información sobre las vulnerabilidades de la víctima**:

  ```bash
  nmap --script "Vuln and safe" (-pXYZ) <Target>
  ```

- #### **Script Auth**:
  Con el script **Auth** podemos comprobar si existen contraseñas vacías o por defecto en el sistema:
  ```bash
  nmap --script auth <Target>
  ```

- #### **Fuzzer web con HTTP-Enum**:
  También podemos tener un **fuzzer web en nmap** con el script http-enum:
  ```bash
  nmap --script=http-enum <target>
  ```

- #### **Fuerza bruta FTP con FTP-Brute**:
  Otro script interesante es para hacer fuerza bruta FTP con nmap de esta forma:
  ```bash
  nmap --script=ftp-brute --script-args userdb="users.txt",passdb="pass.txt" -p21 <target>
  ```

- #### **Fuerza bruta SSH con SSH-Brute**:
  También podemos hacer ataques de fuerza bruta con SSH-Brute:
  ```bash
  nmap --script=ssh-brute --script-args userdb="users.txt",passdb="pass.txt" -p22 <target>
  ```

- #### **Detección de vulnerabilidades en el firewall**:
  Para detectar vulnerabilidades en el firewall podemos utilizar este parámetro:
  ```bash
  nmap -n -Pn -v --script firewall-bypass --script-args firewall-bypass.helper="fpt",firewall-bypass.target=22 "target"
```

## EVASIÓN DE FIREWALL CON NMAP
Un firewall es un sistema que se encarga de controlar las conexiones entrantes y salientes de una red determinada. Incluso también es posible que un puerto se encuentre como filtrado, lo que significa que hay algo que no está impidiendo conocer con exactitud ese puerto, tal y como nos explican en la páginas man de nmap:
Algunas técnicas para evadir firewalls utilizando Nmap incluyen:

- `-f; --mtu <valor>`: Fragmentar paquetes (opcionalmente con el MTU indicado).
- `-S <Dirección_IP>`: Falsificar la dirección IP de origen.
- `-e <interfaz>`: Utilizar la interfaz indicada.
- `-g/ --source-port <numpuerto>`: Utilizar el número de puerto dado.
- `--data-length <num>`: Agregar datos aleatorios a los paquetes enviados.
- `--ttl <val>`: Fijar el valor del campo Time-To-Live (TTL) de IP.

## GUARDAR TRÁFICO DE NMAP EN FICHERO .CAP CON TCPDUMP

Podemos utilizar tcpdump para guardar un determinado tráfico que corre por una interfaz dentro de un fichero con extensión .cap  

Lo haríamos de la siguiente forma, donde primero nos ponemos en escucha con tcpdump guardando el tráfico en un fichero y por la interfaz correspondiente:

![Pasted image 20230412012426.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012426.png?1681277066000)

Y ahora mientras se queda en escucha, vamos a probar por ejemplo en lanzarnos a nosotros mismos un escaneo por el puerto 22 por ejemplo:

![Pasted image 20230412012708.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012708.png?1681277228000)

Se hace el reporte:

![Pasted image 20230412012729.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012729.png?1681277250000)

Y ya tenemos el fichero .cap con el tráfico interceptado:


![Pasted image 20230412012801.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012801.png?1681277282000)

Ahora lanzamos wireshark con la captura:
![Pasted image 20230412012839.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012839.png?1681277320000)

![Pasted image 20230412012855.png](app://e9b7d02ea7b118ed278c747f9e4e75306056/D:/IFP/CIBER/conocimientoo/conocimiento/conocimiento/images/Pasted%20image%2020230412012855.png?1681277336000)

