
## Tratamiento de la TTY

**Explicación y Funcionalidades:**
El tratamiento de la TTY se refiere a las técnicas y herramientas utilizadas para ==mejorar la experiencia y funcionalidad de las sesiones de terminal en sistemas UNIX==. Permite ajustar la configuración de la terminal, ==mejorar la visibilidad== de la salida y ==optimizar la interacción con el sistema==.

**Utilidad en Conexión y Escalada de Privilegios:**
Una vez ==accedemos== a un equipo Linux ==con una reverse shell de Netcat==, veremos que ==andamos a ciegas, lo que hace que incluso no podamos utilizar servicios que corran en interactivo== (Python, mysql, etc.).



## Cheatsheet Tratamiento TTY

### Cargamos una pseudoconsola sobre el sistema

Tenemos 2 formas de hacer esto, la primera es la siguiente:
```bash
script /dev/null -c bash
```

Otra de ellas es a través de python, para ello se recomienda aplicar un `whereis python` a nivel de sistema para comprobar las versiones que se encuentran presentes en el sistema, así tendremos que aplicar el siguiente comando seguido de su versión `python (2,3)`:

``` bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

### Configuramos las variables de entorno correctamente
Dejaremos nuestra sesión en segundo plano con:
``` bash
Ctrl+Z
```

Una vez hecho, aplicamos los siguientes comandos:
```bash
stty raw -echo
```
(Es normal notar que al introducir el primer comando, `stty raw -echo`, no visualizamos lo que se está escribiendo, aunque los caracteres se están ingresando.)


```bash
fg
```
Este comando nos devuelve a la sesión que teníamos a través de Netcat.

Al emplear el comando `reset`, reconfiguramos nuestra sesión, y en la mayoría de los casos, nos solicita el tipo de terminal con el que deseamos trabajar
``` bash
reset
```
Al momento de solicitar el tipo de terminal escribimos:
```bash
xterm
```


En el caso de que no lo solicite o incluso si lo hace, después aplicamos los siguientes comandos:
```bash
export TERM=xterm
export SHELL=bash
```

`Opcionalmente` redimensionaremos la terminal.  pues en caso de abrir algún editor como nano, veremos que las proporciones no cuadran. Para ello, lo más recomendable es poner a tamaño completo la terminal.

Abrimos otra terminal en nuestro sistema con el mismo redimensionamiento, y aplicamos el siguiente comando:

```bash
ssty -a
```
Que nos otorgará como respuesta la configuración de nuestra terminal. De esta información nos interesan las `rows` y `colums`

Copiamos dicha configuración en la máquina que hemos comprometido donde se ha llevado a cabo toda la previa configuración, aplicando para ello el siguiente comandos:

```bash
stty rows xx colums  yy
```

El resultado final será una Shell completamente interactiva, donde nos sentiremos como si hubiéramos ganado acceso por SSH, con capacidad de tabulación, uso de Shortcuts (Ctrl+C, Ctrl+L, etc.), sesiones interactivas, etc.