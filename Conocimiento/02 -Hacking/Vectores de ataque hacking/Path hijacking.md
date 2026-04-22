---
Escalada de privilegios: 
Permisos de archivos: 
Tecnicas Hacking:
---
## Path hijacking

**Explicación y Funcionalidades:**
La técnica de Path Hijacking, también conocida como "DLL Hijacking" en entornos Windows, es un vector de ataque que aprovecha la forma en que los sistemas operativos buscan y cargan archivos ejecutables y bibliotecas compartidas. Consiste en ==manipular el PATH del sistema o la variable de entorno de la biblioteca compartida para que apunte a una ubicación maliciosa donde se encuentra un archivo con el mismo nombre que el ejecutable o la biblioteca requerida por un programa legítimo. De esta manera, un atacante puede engañar al sistema para cargar y ejecutar su código malicioso en lugar del archivo legítimo.==



**Papel en la Ciberseguridad:**
Path Hijacking es una técnica comúnmente utilizada por atacantes para comprometer sistemas y ejecutar código malicioso de forma encubierta. Puede conducir a una [[escalada de privilegios]], ejecución de comandos remotos, exfiltración de datos y otros tipos de ataques, lo que lo convierte en una preocupación importante para la ciberseguridad.



## Cheatsheet de Path Hijacking:

### 1. Identificar archivos ejecutables o bibliotecas compartidas vulnerables.
   - Buscar programas que utilicen rutas relativas o que no especifiquen la ruta completa al archivo.
#### Para buscar y listar programas vulnerables a Path Hijacking:
1. **Find:**
   Puedes usar el comando `find` para buscar programas que utilicen rutas relativas o que no especifiquen la ruta completa al archivo. Por ejemplo:
   ```bash
   find / -perm /u+s -type f 2>/dev/null
   ```
   Esto buscará archivos con permisos suid en todo el sistema y los listará.

2. **Ldconfig:** 
   El comando `ldconfig` puede mostrar bibliotecas compartidas y sus rutas. Puedes revisar las rutas buscando posibles ubicaciones que puedan ser manipuladas.
3. **Readelf:**
   La herramienta `readelf` puede examinar la estructura de archivos binarios ELF (Executable and Linkable Format). Puedes usarlo para examinar los archivos ejecutables y buscar información sobre las bibliotecas compartidas que utilizan.

#### Para listar los binarios que tengan permisos suid o sugd:

1. **Find:**
   Puedes usar el comando `find` para buscar archivos con permisos suid o sugd. Por ejemplo:
   ```bash
   find / -type f \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
   ```
   Esto buscará archivos con permisos suid o sugd en todo el sistema y los listará con detalles.

2. **Ls:**
   El comando `ls` también puede utilizarse para listar archivos con permisos suid o sugd en un directorio específico. Por ejemplo:
   ```bash
   ls -l /bin /sbin /usr/bin /usr/sbin | grep -E '^(...s|....s)'
   ```
   Esto mostrará los archivos en los directorios binarios que tienen permisos suid o sugd.

3. **Find con Permiso Específico:**
   Puedes usar `find` con permisos específicos para buscar archivos suid o sugd en todo el sistema:
   ```bash
   find / -perm /u+s -o -perm /g+s -exec ls -l {} \; 2>/dev/null
   ```
   Esto buscará archivos con permisos suid o sugd en todo el sistema y los listará con detalles.

Estas son algunas opciones que puedes usar para buscar y listar programas vulnerables a ataques de Path Hijacking o con permisos suid/sugd en sistemas Unix/Linux. Es importante realizar estas verificaciones regularmente para mantener la seguridad del sistema.

### 2. Crear un archivo malicioso con el mismo nombre que el ejecutable o la biblioteca vulnerable.
   - El archivo malicioso contiene código que se ejecutará en lugar del archivo legítimo.
### 3. Colocar el archivo malicioso en una ubicación que esté antes en el PATH del sistema que la ubicación del archivo legítimo.
   - Esto asegura que el sistema cargue primero el archivo malicioso cuando se busque el archivo requerido.

1. **Movimiento Manual:**
   Puedes mover manualmente el archivo malicioso a un directorio que esté antes en el PATH del sistema que la ubicación del archivo legítimo. Por ejemplo, si deseas reemplazar un ejecutable legítimo en `/usr/local/bin`, puedes mover tu archivo malicioso a ese directorio.

   ```bash
   mv archivo_malicioso /usr/local/bin
   ```

2. **Creación de Enlaces Simbólicos:**
   Puedes crear enlaces simbólicos desde directorios que estén antes en el PATH hacia tu archivo malicioso. Esto puede permitir que tu archivo malicioso sea ejecutado en lugar del archivo legítimo. Por ejemplo:

   ```bash
   ln -s /ruta/a/tu/archivo_malicioso /usr/local/bin/ejecutable_legitimo
   ```

3. **Manipulación del PATH:**
   Si tienes permisos de administrador en el sistema, puedes modificar la variable de entorno PATH para incluir la ubicación del archivo malicioso antes que la ubicación del archivo legítimo. Sin embargo, esto puede requerir privilegios elevados y puede ser detectado por herramientas de seguridad.

4. **Uso de Scripts de Inicialización:**
   Puedes crear scripts de inicialización que establezcan el PATH de forma personalizada al iniciar sesión en el sistema. Estos scripts pueden modificar temporalmente el PATH para incluir la ubicación de tu archivo malicioso.

### 4. Esperar a que el programa legítimo sea ejecutado por el usuario o el sistema.
   - Cuando el programa legítimo intenta cargar el archivo necesario, el sistema carga el archivo malicioso en su lugar.
### 5. El código malicioso se ejecuta, permitiendo al atacante obtener acceso no autorizado o realizar acciones no permitidas por los permisos que corresponden al usuario en el sistema.



## Prevenir Path Hijacking: 

- Evita usar rutas relativas en scripts y comandos. 
- Usa rutas absolutas para ejecutables conocidos. 
- Revisa y ajusta adecuadamente los permisos de archivos y directorios. 
- Limita los privilegios de los usuarios y utiliza la autenticación multifactor cuando sea posible.



## Ejemplos:

### Ejemplo con Salida Satisfactoria:

Un atacante coloca un archivo malicioso llamado `ls` en un directorio que está antes en el PATH que el directorio donde se encuentra el verdadero `ls`. Cuando el usuario ejecuta `ls`, el sistema ejecuta el archivo malicioso en lugar del comando legítimo.

### Ejemplo con Salida Fallida:

Un sistema está configurado con rutas absolutas en lugar de rutas relativas en todos los scripts y comandos. Esto hace que sea más difícil para un atacante manipular el PATH con éxito y ejecutar un archivo malicioso en lugar de un comando legítimo. Aunque el atacante intente realizar Path Hijacking, el sistema no ejecutará el archivo malicioso porque el PATH no se usa para buscar ejecutables.



## Alternativas a Path Hijacking como Vector de Ataque:

Algunas alternativas a Path Hijacking incluyen:
- **DLL Injection:** Inyectar código malicioso en procesos en ejecución para ejecutar acciones no autorizadas.
- **Malware de Ingeniería Social:** Engañar a los usuarios para que ejecuten malware descargado o adjunto en correos electrónicos, enlaces maliciosos, etc.
- **Exploits de Software:** Aprovechar vulnerabilidades conocidas en software y sistemas operativos para obtener acceso no autorizado.


## Máquinas:
